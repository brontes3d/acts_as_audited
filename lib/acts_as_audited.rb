# Copyright (c) 2006 Brandon Keepers
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

module ActsAsAudited
  
  def self.without_auditing(*models, &block)
    to_call = block
    models.each do |m| 
      inner = to_call
      to_call = Proc.new do 
        m.without_auditing do
          inner.call
        end
      end
    end
    to_call.call
  end
  
  #
  # Audit saves the changes to ActiveRecord models.  It has the following attributes:
  #
  # * <tt>auditable</tt>: the ActiveRecord model that was changed
  # * <tt>user</tt>: the user that performed the change; a string or an ActiveRecord model
  # * <tt>action</tt>: one of create, update, or delete
  # * <tt>audit_changes</tt>: a serialized hash of all the audit_changes
  # * <tt>created_at</tt>: Time that the change was performed
  #
  module Audit
    def self.included(base)
      base.class_eval do
          belongs_to :auditable, :polymorphic => true
          belongs_to :user, :polymorphic => true

          before_create :set_version_number

          serialize :audit_changes

          cattr_accessor :audited_classes
          self.audited_classes = []

          # Allows user to be set to either a string or an ActiveRecord object
          def user_as_string=(user) #:nodoc:
            # reset both either way
            self.user_as_model = self.username = nil
            user.is_a?(ActiveRecord::Base) ?
              self.user_as_model = user :
              self.username = user
          end
          alias_method :user_as_model=, :user=
          alias_method :user=, :user_as_string=

          def user_as_string #:nodoc:
            self.user_as_model || self.username
          end
          alias_method :user_as_model, :user
          alias_method :user, :user_as_string

          def revision
            attributes = self.class.reconstruct_attributes(ancestors).merge({:version => version})
            clazz = auditable_type.constantize
            returning clazz.find_by_id(auditable_id) || clazz.new do |m|
              m.attributes = attributes
            end
          end

          def ancestors
            self.class.find(:all, :order => 'version',
              :conditions => ['auditable_id = ? and auditable_type = ? and version <= ?',
              auditable_id, auditable_type, version])
          end

          def self.reconstruct_attributes(audits)
            audit_changes = {}
            result = audits.collect do |audit|
              attributes = (audit.audit_changes || {}).inject({}) do |attrs, (name, (_,value))|
                attrs[name] = value
                attrs
              end
              audit_changes.merge!(attributes.merge!(:version => audit.version))
              yield audit_changes if block_given?
            end
            block_given? ? result : audit_changes
          end

        protected
        
          def set_version_number
            max = self.class.maximum(:version,
              :conditions => {
                :auditable_id => auditable_id,
                :auditable_type => auditable_type
              }) || 0
            self.version = max + 1
          end
      end
    end
  end
end

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
    module Audited #:nodoc:
      CALLBACKS = [:audit_create, :audit_update, :audit_destroy]

      def self.included(base) # :nodoc:
        base.extend ClassMethods
      end

      module ClassMethods
        # == Configuration options
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
        def acts_as_audited(options = {})
          
          # don't allow multiple calls
          return if self.included_modules.include?(CollectiveIdea::Acts::Audited::InstanceMethods)

          include CollectiveIdea::Acts::Audited::InstanceMethods
          
          class_inheritable_reader :non_audited_columns

          except = [self.primary_key, inheritance_column, 'lock_version', 'created_at', 'updated_at']
          except |= [options[:except]].flatten.collect(&:to_s) if options[:except]
          write_inheritable_attribute :non_audited_columns, except

          class_eval do
            cattr_accessor :auditing_enabled
            self.auditing_enabled = true
            
            extend CollectiveIdea::Acts::Audited::SingletonMethods

            has_many :audits, :as => :auditable, :order => 'audits.version desc'
            attr_protected :audit_ids
            Audit.audited_classes << self unless Audit.audited_classes.include?(self)
            
            after_create :audit_create
            after_update :audit_update
            after_destroy :audit_destroy
            
            attr_accessor :version            
          end
        end
      end
    
      module InstanceMethods
        
        def audit_changed_attributes
          excepted_changes
        end
        
        # Temporarily turns off auditing while saving.
        def save_without_auditing
          without_auditing { save }
        end
      
        # Returns an array of attribute keys that are audited.  See non_audited_columns
        def audited_attributes
          self.attributes.keys.select { |k| !self.non_audited_columns.include?(k) }
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
        
        # Gets an array of the revisions available
        #
        #   user.revisions.each do |revision|
        #     user.name
        #     user.version
        #   end
        #
        def revisions(from_version = 1)
          audit_changes(from_version) {|attributes| revision_with(attributes) }
        end
        
        # Get a specific revision
        def revision(version)
          revision_with audit_changes(version)
        end
        
        def revision_at(date_or_time)
          audit = audits.find(:first, :conditions => ["created_at <= ?", date_or_time],
            :order => "created_at DESC")
          revision_with audit_changes(audit.version) if audit
        end
        
        # If called with no parameters, gets whether the current model has changed.
        # If called with a single parameter, gets whether the parameter has changed.
        def audit_changed?(attr_name = nil)
          attr_name ? excepted_changes[attr_name.to_s] : !excepted_changes.empty?
        end
        
        def excepted_changes
          excepted_changes = {}
          self.changes.each do |key,value|
            unless non_audited_columns.include?(key)
              excepted_changes[key] = value
            end
          end
          excepted_changes
        end        

      private
      
        def audit_changes(from_version = 1)
          from_version = audits.find(:first).version if from_version == :previous
          audit_changes = {}
          result = audits.find(:all, :conditions => ['version >= ?', from_version]).collect do |audit|
            attributes = (audit.audit_changes || {}).inject({}) do |attrs, (name, values)|
              attrs[name] = values.first
              attrs
            end
            audit_changes.merge!(attributes.merge!(:version => audit.version))
            yield audit_changes if block_given?
          end
          block_given? ? result : audit_changes
        end
        
        def revision_with(attributes)
          returning self.dup do |revision|
            revision.send :instance_variable_set, '@attributes', self.attributes_before_type_cast
            revision.attributes = attributes
          end
        end
        
        # Creates a new record in the audits table if applicable
        def audit_create
          if self.class.auditing_enabled
            write_audit(:create)
          end
          true
        end

        def audit_update
          if self.class.auditing_enabled
            write_audit(:update) if audit_changed?
          end
          true
        end

        def audit_destroy
          if self.class.auditing_enabled
            write_audit(:destroy)
          end
          true
        end
        
        def write_audit(action = :update, user = nil)
          self.audits.create :audit_changes => excepted_changes, :action => action.to_s, :user => user
        end
        
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
          auditing_was_enabled = auditing_enabled
          disable_auditing
          block.call
        ensure
          enable_auditing if auditing_was_enabled
        end
        
        def disable_auditing
          self.auditing_enabled = false
        end
        
        def enable_auditing
          self.auditing_enabled = true
        end

      end
    end
  end
end
