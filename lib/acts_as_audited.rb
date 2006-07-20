# Copyright (c) 2005 Brandon Keepers
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

module CollectiveIdea #:nodoc:
  module Acts #:nodoc:
    # Specify this act if you want changes to your model to be saved in an
    # audit table.  This assumes there is an audits table ready.
    #
    #   class User < ActiveRecord::Base
    #     acts_as_audited
    #   end
    #
    # See <tt>CollectiveIdea::Acts::Audited::ClassMethods#acts_as_audited</tt>
    # for configuration options
    module Audited
      CALLBACKS = [:clear_changed_attributes, :save_audit]

      def self.included(base) # :nodoc:
        base.extend ClassMethods
      end

      module ClassMethods
        # == Configuration options
        #
        # * <tt>if</tt> - symbol of method to check before saving an audit log.
        #   If this method returns false, an audit log is not saved. For finer
        #   control, pass either a Proc or modify Model#audit_condition_met?
        #
        #     acts_as_audited :if => Proc.new { |auction| !auction.expired? }
        #
        #   or...
        #
        #     class Auction
        #       def audit_condition_met? # totally bypasses the <tt>:if</tt> option
        #         !expired?
        #       end
        #     end
        #
        # * <tt>except</tt> - Excludes fields from being saved in the audit log.
        #   By default, acts_as_audited will audit all but these fields: 
        # 
        #     [self.primary_key, inheritance_column, 'lock_version', 'created_at', 'updated_at']
        #
        #   You can add to those by passing one or an array of fields to skip.
        #
        #     class User < ActiveRecord::Base
        #       acts_as_audited :except => :password
        #     end
        # 
        #
        # == Database Schema
        #
        # The model that you're versioning needs to have a 'version' attribute. The model is versioned 
        # into a table called #{model}_versions where the model name is singlular. The _versions table should 
        # contain all the fields you want versioned, the same version column, and a #{model}_id foreign key field.
        #
        # A lock_version field is also accepted if your model uses Optimistic Locking.  If your table uses Single Table inheritance,
        # then that field is reflected in the versioned model as 'versioned_type' by default.
        #
        # Acts_as_versioned comes prepared with the ActiveRecord::Acts::Versioned::ActMethods::ClassMethods#create_versioned_table 
        # method, perfect for a migration.  It will also create the version column if the main model does not already have it.
        #
        #   class AddVersions < ActiveRecord::Migration
        #     def self.up
        #       # create_versioned_table takes the same options hash
        #       # that create_table does
        #       Post.create_versioned_table
        #     end
        #   
        #     def self.down
        #       Post.drop_versioned_table
        #     end
        #   end
        # 
        def acts_as_audited(options = {})
          # don't allow multiple calls
          return if self.included_modules.include?(CollectiveIdea::Acts::Audited::InstanceMethods)

          class_eval do
            extend CollectiveIdea::Acts::Audited::SingletonMethods
          end
          include CollectiveIdea::Acts::Audited::InstanceMethods
          
          cattr_accessor :audit_condition, :non_audited_columns
          
          attr_accessor :changed_attributes

          self.audit_condition = options[:if] || true
          self.non_audited_columns = [self.primary_key, inheritance_column, 'lock_version', 'created_at', 'updated_at']
          self.non_audited_columns |= options[:except].is_a?(Array) ?
            options[:except].collect{|column| column.to_s} : [options[:except].to_s] if options[:except]

          class_eval do
            has_many :audits, :as => :auditable, :dependent => :nullify
            after_save :save_audit
            after_save :clear_changed_attributes
          end
        end
      end
    
      module InstanceMethods
        # Creates a new record in the audits table if applicable
        def save_audit
          audits.create(:changes => changed_attributes.inspect, :user => User.current_user) if save_audit?
        end

        # Temporarily turns off auditing while saving.
        def save_without_auditing
          without_auditing do
            save
          end
        end
      
        # Returns an array of attribute keys that are audited.  See non_audited_columns
        def audited_attributes
          self.attributes.keys.collect { |k| !self.class.non_audited_columns.include?(k) }
        end
        
        # If called with no parameters, gets whether the current model has changed.
        # If called with a single parameter, gets whether the parameter has changed.
        def changed?(attr_name = nil)
          attr_name.nil? ?
            (changed_attributes && changed_attributes.length > 0) :
            (changed_attributes && changed_attributes.include?(attr_name.to_s))
        end
        
        # Checks whether a new audit record should be saved.  Calls <tt>audit_condition_met?</tt> and <tt>changed?</tt>.
        def save_audit?
          audit_condition_met? && changed?
        end
        
        # Checks condition set in the :if option to check whether or not to record audit logs.  Override this for
        # custom condition checking.
        def audit_condition_met?
          case
          when audit_condition.is_a?(Symbol)
            send(audit_condition)
          when audit_condition.respond_to?(:call) && (audit_condition.arity == 1 || audit_condition.arity == -1)
            audit_condition.call(self)
          else
            audit_condition
          end          
        end

        # Executes the block with the auditing callbacks disabled.
        #
        #   @foo.without_auditing do
        #     @foo.save
        #   end
        #
        def without_auditing(&block)
          self.class.without_auditing(&block)
        end

        private
          # clears current changed attributes.  Called after save.
          def clear_changed_attributes
            self.changed_attributes = {}
          end
          
          def write_attribute(attr_name, attr_value)
            (self.changed_attributes ||= {})[attr_name.to_s] = [read_attribute(attr_name), attr_value] unless self.changed?(attr_name) or self.send(attr_name) == attr_value
            super(attr_name.to_s, attr_value)
          end

          CALLBACKS.each do |attr_name| 
            alias_method "orig_#{attr_name}".to_sym, attr_name
          end
          
          def empty_callback() end #:nodoc:

      end # InstanceMethods
      
      module SingletonMethods
        # Returns an array of columns that are audited.  See non_audited_columns
        def audited_columns
          self.columns.select { |c| !non_audited_columns.include?(c.name) }
        end

        # Executes the block with the auditing callbacks disabled.
        #
        #   Foo.without_auditing do
        #     @foo.save
        #   end
        #
        def without_auditing(&block)
          class_eval do 
            CALLBACKS.each do |attr_name| 
              alias_method attr_name, :empty_callback
            end
          end
          result = block.call
          class_eval do 
            CALLBACKS.each do |attr_name|
              alias_method attr_name, "orig_#{attr_name}".to_sym
            end
          end
          result
        end
      end
    end
  end
end

ActiveRecord::Base.send :include, CollectiveIdea::Acts::Audited