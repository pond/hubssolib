namespace :deploy do

  desc 'Compare asset timestamps with the manifest file, to see if precompiled assets are outdated'
  task :check => :environment do | t, args |
    puts "Checking precompiled assets for #{Rails.application.name.titleize}..."

    dev_assets_folder_path = Rails.root.join('app', 'assets', 'builds')
    manifest_file_path     = Rails.root.join('public', 'assets', '.manifest.json')
    manifest_updated_at    = File.mtime(manifest_file_path) rescue nil

    if manifest_updated_at.nil?
      abort('ERROR: Production assets have not been precompiled or are damaged') # NOTE EARLY EXIT
    end

    assets_updated_at = Rails.application.config.assets.paths.map do | asset_folder_path |
      next if asset_folder_path == dev_assets_folder_path # NOTE EARLY LOOP RESTART

      path_assets_updated_at = Dir.glob("#{asset_folder_path}/**/*").map do | asset_file_path |
        File.mtime(asset_file_path)
      end

      path_assets_updated_at.compact.max() # Most recent timestamp
    end

    newest_asset_updated_at = assets_updated_at.compact.max()

    # NOTE EARLY EXITS
    #
    if newest_asset_updated_at.nil?
      abort('ERROR: Could not determine asset age! Assets may be missing?')
    elsif newest_asset_updated_at > manifest_updated_at
      abort('ERROR: Production assets are outated; run "rake assets:productionize"')
    end

    puts('...Done. Precompiled assets are up to date.')
  end

  desc 'Clobber and precompile assets for Production and a given relative URL root, regardless of current RAILS_ENV'
  task :build, [:url_root] => :environment do | t, args |
    if args[:url_root].nil?
      puts
      puts 'ERROR: You must provide an argument for RAILS_RELATIVE_URL_ROOT,'
      puts '       so that compiled URLs are built correctly. If you want to'
      puts '       serve from the actual root, pass an empty string. E.g.:'
      puts
      puts '         bundle exec rake \'assets:productionize[forum]\''
      puts '         bundle exec rake \'assets:productionize[""]\''
      puts
      abort('       Halting.')
    end

    url_root = args[:url_root]
    url_root = "/#{url_root}" unless url_root.start_with?('/')

    # Can't use "Rake::Task['foo'].invoke" (for example) as Rails has already
    # booted for *this* task with whatever environment was on the CLI and in
    # turn, Propshaft's Railtie, where it reads relative URL root, has already
    # run. We could try to hack config, but we just can't be sure where within
    # its internals Propshaft might have cached any of that data, so we must
    # use the slow path of rebooting the full stack with the correct env.
    #
    system(
      {
        "RAILS_ENV"               => "production",
        "RAILS_RELATIVE_URL_ROOT" => url_root
      },
      'bundle exec rake assets:clobber assets:precompile'
    )
  end

end
