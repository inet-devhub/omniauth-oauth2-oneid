# frozen_string_literal: true

require "bundler/gem_tasks"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "lib" << "test"
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = false
end

desc "Check dependencies against the Ruby advisory database"
task :audit do
  sh "bundle exec bundle-audit check --update"
end

task default: %i[test]
