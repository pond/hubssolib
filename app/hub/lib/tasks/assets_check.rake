namespace :assets do

  desc 'Check timestamps to see if precompiled assets are outdated'
  task :check_precompiled => :environment do | t, args |
    puts "Checking precompiled assets for #{Rails.application.name.titleize}..."

    dev_assets_folder_path = Rails.root.join('app', 'assets', 'builds')
    manifest_file_path     = Rails.root.join('public', 'assets', '.manifest.json')
    manifest_updated_at    = File.mtime(manifest_file_path) rescue nil

    if manifest_updated_at.nil?
      abort('Production assets have not been precompiled or are damaged') # NOTE EARLY EXIT
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
      abort('Could not determine asset age! Assets may be missing?')
    elsif newest_asset_updated_at > manifest_updated_at
      abort('Production assets are outdated')
    end

    puts('...Done. Precompiled assets are up to date.')
  end

  desc 'Clobber and precompile assets for Production, regardless of current RAILS_ENV'
  task :productionize => :environment do | t, args |
    Rails.env = 'production' # Here be dragons!

    Rake::Task['assets:clobber'].invoke
    Rake::Task['assets:precompile'].invoke
  end

end
