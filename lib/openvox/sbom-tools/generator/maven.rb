require 'fileutils'
require 'json'
require 'set'
require 'tmpdir'

require_relative '../generator'
require_relative '../exec'
require_relative '../http'

module OpenVox::SBOMTools::Generator
  class Maven
    include OpenVox::SBOMTools::Exec
    include OpenVox::SBOMTools::HTTP

    CYCLONEDX_PLUGIN_VERSION = '2.9.2'.freeze

    MAVEN_CENTRAL = 'https://repo1.maven.org/maven2'.freeze

    attr_reader :file, :project, :tag

    def initialize(file, project, tag)
      @file    = file
      @project = project
      @tag     = tag
    end

    def generate!
      workdir = Dir.mktmpdir
      $stderr.puts format('Assembling SBOM for %<project>s@%<tag>s in: %<workdir>s',
                          project:, tag:, workdir:)

      artifact = case @project
                 when 'openvox-server'
                   'puppetserver'
                 when 'openvoxdb'
                   'puppetdb'
                 end

      $stderr.puts format('Downloading pom.xml for: org.openvoxprojct:%<artifact>s:%<tag>s',
                          artifact:, tag:)
      pom_url = format('https://repo.clojars.org/org/openvoxproject/%<artifact>s/%<tag>s/%<artifact>s-%<tag>s.pom',
                       artifact:, tag:)

      get_file(pom_url, File.join(workdir, 'pom.xml'))

      $stderr.puts 'Running: mvn makeAggregateBom'
      exec('mvn', "org.cyclonedx:cyclonedx-maven-plugin:#{CYCLONEDX_PLUGIN_VERSION}:makeAggregateBom",
           '-DprojectType=application',
           workdir:)

      FileUtils.cp(File.join(workdir, 'target', 'bom.json'), @file)

      enrich_with_jruby_stdlib!(workdir)
    end

    # The Maven plugin only reports the JVM dependency graph declared in the POM.
    # The shipped uberjar additionally bundles the JRuby standard library
    # (jruby-stdlib.jar), which vendors the Ruby gems that ship with JRuby as well
    # as jar-in-jar libraries such as BouncyCastle, SnakeYAML and JLine. None of
    # those are visible in the POM, so they are missing from the generated SBOM.
    #
    # This step introspects the jruby-stdlib.jar referenced by the SBOM with Syft
    # and nests the discovered components under the jruby-stdlib component. This
    # mirrors how the Vanagon generator nests bundled gems under the ruby
    # component. Projects that do not bundle JRuby (e.g. openvoxdb) are left
    # untouched.
    def enrich_with_jruby_stdlib!(workdir)
      bom = JSON.parse(File.read(@file))
      components = bom['components'] || []

      stdlib = components.find do |component|
        component['group'] == 'org.jruby' && component['name'] == 'jruby-stdlib'
      end
      return if stdlib.nil?

      version = stdlib['version']
      $stderr.puts format('Enriching SBOM with components bundled in jruby-stdlib %<version>s',
                          version:)

      jar = File.join(workdir, "jruby-stdlib-#{version}.jar")
      jar_url = format('%<repo>s/org/jruby/jruby-stdlib/%<version>s/jruby-stdlib-%<version>s.jar',
                       repo: MAVEN_CENTRAL, version:)
      get_file(jar_url, jar)

      extract = File.join(workdir, 'jruby-stdlib')
      FileUtils.mkdir_p(extract)
      run!('unzip', '-q', jar, '-d', extract)

      # A directory scan triggers both Syft catalogers: ruby-gemspec finds the
      # bundled gems and java-archive finds the embedded jar-in-jar libraries.
      # A scan of the jar file alone misses the gemspecs.
      syft_bom = File.join(workdir, 'jruby-stdlib.cdx.json')
      run!('syft', '-q', 'scan', "dir:#{extract}", '-o', "cyclonedx-json=#{syft_bom}")
      discovered = JSON.parse(File.read(syft_bom))['components'] || []

      nested = select_bundled_components(discovered, components, stdlib)
      stdlib['components'] = nested.sort_by { |component| component['purl'].to_s }

      File.write(@file, JSON.pretty_generate(bom))
      $stderr.puts format('Nested %<count>d bundled components under jruby-stdlib',
                          count: nested.length)
    end

    private

    # Syft's directory scan over-reports, so keep only actionable, de-duplicated
    # signal to nest under jruby-stdlib:
    #   * pkg:gem/*              the bundled Ruby gems
    #   * versioned pkg:maven/*  the embedded Java libraries
    #
    # Dropped as noise: pkg:maven/rubygems/* (gem duplicates in the wrong
    # ecosystem), versionless entries (JRuby's own native extension jars, which
    # carry no version and cannot be matched against advisories) and pkg:github/*
    # (CI workflow references vendored inside gem sources, not shipped code).
    # Components already present at the top level are skipped as well.
    def select_bundled_components(discovered, top_level, stdlib)
      top_level_keys = top_level.map { |component| purl_key(component['purl']) }.compact.to_set
      stdlib_key = purl_key(stdlib['purl'])
      seen = Set.new

      discovered.each_with_object([]) do |component, kept|
        purl = component['purl']
        next unless keep?(purl)

        key = purl_key(purl)
        next if key == stdlib_key || top_level_keys.include?(key)
        next unless seen.add?(key)

        entry = {'type'    => component['type'] || 'library',
                 'name'    => component['name'],
                 'version' => component['version'],
                 'purl'    => purl}
        entry['bom-ref'] = component['bom-ref'] if component['bom-ref']
        kept << entry
      end
    end

    def keep?(purl)
      return false if purl.nil?
      return true if purl.start_with?('pkg:gem/')
      return false unless purl.start_with?('pkg:maven/')
      return false if purl.start_with?('pkg:maven/rubygems/')

      # Require a version so unidentified native extension jars are dropped.
      purl.include?('@')
    end

    # Strip PURL qualifiers so that, for example,
    # pkg:maven/org.bouncycastle/bcprov-jdk18on@1.84?type=jar and the same PURL
    # without qualifiers compare as equal.
    def purl_key(purl)
      return nil if purl.nil?

      purl.split('?', 2).first
    end

    # Run a command via Exec#exec and raise if it fails, so an incomplete SBOM is
    # never written silently.
    def run!(*command_line)
      result = exec(*command_line)
      return result if result.success?

      raise format("Command failed: %<cmd>s\n%<stderr>s",
                   cmd: command_line.join(' '), stderr: result.stderr)
    end
  end
end
