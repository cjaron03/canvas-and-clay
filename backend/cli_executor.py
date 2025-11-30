"""CLI command executor for admin console.

Executes validated CLI commands using ORM models.
"""
import json
from datetime import datetime, date, timezone
from typing import Dict, Any, Optional, List
from flask import current_app, request
from sqlalchemy.exc import IntegrityError
from flask_limiter.util import get_remote_address

from cli_parser import CLIParseError, CLIParser


class CLIExecutionError(Exception):
    """Error raised when CLI command execution fails."""
    pass


class CLIExecutor:
    """Executor for CLI commands using ORM."""
    
    def __init__(self, db, models):
        """Initialize executor with database and models.
        
        Args:
            db: SQLAlchemy database instance
            models: Dictionary of model classes (Artist, Artwork, etc.)
        """
        self.db = db
        self.models = models
    
    def execute(self, parsed_command: Dict[str, Any], write_mode: bool = False, user_id: int = None, user_email: str = None) -> Dict[str, Any]:
        """Execute a parsed CLI command.
        
        Args:
            parsed_command: Parsed command from CLIParser
            write_mode: Whether write operations are allowed
            user_id: User ID for audit logging
            user_email: User email for audit logging
            
        Returns:
            Dictionary with execution results:
            {
                'success': bool,
                'output': str,
                'data': Any,
                'requires_confirmation': bool
            }
            
        Raises:
            CLIExecutionError: If execution fails
        """
        action = parsed_command['action']
        entity = parsed_command['entity']
        entity_id = parsed_command.get('entity_id')
        options = parsed_command.get('options', {})
        positional_args = parsed_command.get('positional_args', [])
        is_read_only = parsed_command['is_read_only']
        
        # Check write mode for non-read-only operations
        if not is_read_only and not write_mode:
            raise CLIExecutionError('Write mode must be enabled for this operation. Enable write mode and try again.')
        
        try:
            if action == 'help':
                return self._execute_help()
            elif action == 'stats':
                return self._execute_stats()
            elif action == 'list':
                return self._execute_list(entity, options)
            elif action == 'show':
                return self._execute_show(entity, entity_id)
            elif action == 'create':
                return self._execute_create(entity, positional_args, options, user_id, user_email)
            elif action == 'update':
                return self._execute_update(entity, entity_id, options, user_id, user_email)
            elif action == 'delete':
                # Delete requires confirmation - return confirmation request
                return self._execute_delete_preview(entity, entity_id)
            elif action == 'start_deletion_scheduler':
                return self._execute_start_deletion_scheduler()
            elif action == 'stop_deletion_scheduler':
                return self._execute_stop_deletion_scheduler()
            else:
                raise CLIExecutionError(f'Unknown action: {action}')
        except Exception as e:
            current_app.logger.exception(f'CLI execution error: {str(e)}')
            raise CLIExecutionError(str(e))
    
    def execute_delete(self, entity: str, entity_id: str, user_id: int = None, user_email: str = None) -> Dict[str, Any]:
        """Execute a delete operation (after confirmation).
        
        Args:
            entity: Entity type
            entity_id: Entity ID to delete
            user_id: User ID for audit logging
            user_email: User email for audit logging
            
        Returns:
            Dictionary with deletion results
        """
        try:
            model = self._get_model(entity)
            record = model.query.get(entity_id)
            
            if not record:
                raise CLIExecutionError(f'{entity.capitalize()} with ID {entity_id} not found')
            
            # Get record details before deletion
            record_data = self._serialize_record(record, entity)
            
            # Delete the record
            self.db.session.delete(record)
            self.db.session.commit()
            
            # Log to audit log
            if user_id is not None:
                self._log_audit_event(
                    f'cli_delete_{entity}',
                    user_id=user_id,
                    email=user_email,
                    details={'entity': entity, 'entity_id': entity_id, 'deleted_data': record_data}
                )
            
            return {
                'success': True,
                'output': f'Successfully deleted {entity} {entity_id}',
                'data': {'deleted': record_data},
                'requires_confirmation': False
            }
        except IntegrityError as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Cannot delete {entity} {entity_id}: {str(e)}')
        except Exception as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Failed to delete {entity} {entity_id}: {str(e)}')
    
    def _execute_help(self) -> Dict[str, Any]:
        """Execute help command."""
        help_info = CLIParser.get_help()
        return {
            'success': True,
            'output': 'Available commands and examples',
            'data': help_info,
            'requires_confirmation': False
        }
    
    def _execute_stats(self) -> Dict[str, Any]:
        """Execute stats command."""
        from datetime import datetime, timezone, timedelta
        
        stats = {}
        for entity_name in CLIParser.ENTITIES.keys():
            model = self._get_model(entity_name)
            stats[entity_name] = model.query.count()
        
        return {
            'success': True,
            'output': 'System statistics',
            'data': stats,
            'requires_confirmation': False
        }
    
    def _execute_list(self, entity: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute list command."""
        model = self._get_model(entity)
        query = model.query
        
        # Apply filters from options
        if 'artist' in options and entity == 'artwork':
            query = query.filter(model.artist_id == options['artist'])
        elif 'artist_id' in options and entity == 'artwork':
            query = query.filter(model.artist_id == options['artist_id'])
        
        # Limit results
        limit = options.get('limit', 100)
        if limit > 1000:
            limit = 1000
        
        records = query.limit(limit).all()
        
        data = [self._serialize_record(record, entity) for record in records]
        
        return {
            'success': True,
            'output': f'Found {len(data)} {entity}(s)',
            'data': data,
            'requires_confirmation': False
        }
    
    def _execute_show(self, entity: str, entity_id: str) -> Dict[str, Any]:
        """Execute show command."""
        model = self._get_model(entity)
        record = model.query.get(entity_id)
        
        if not record:
            raise CLIExecutionError(f'{entity.capitalize()} with ID {entity_id} not found')
        
        data = self._serialize_record(record, entity)
        
        return {
            'success': True,
            'output': f'{entity.capitalize()} {entity_id}',
            'data': data,
            'requires_confirmation': False
        }
    
    def _execute_create(self, entity: str, positional_args: List[Any], options: Dict[str, Any], user_id: int = None, user_email: str = None) -> Dict[str, Any]:
        """Execute create command."""
        model = self._get_model(entity)
        entity_info = CLIParser.ENTITIES[entity]
        
        # Build data dictionary
        data = {}
        
        # Handle positional arguments based on entity
        if entity == 'artist':
            if len(positional_args) < 3:
                raise CLIExecutionError('create artist requires: ID, first_name, last_name')
            data['artist_id'] = positional_args[0]
            data['artist_fname'] = positional_args[1]
            data['artist_lname'] = positional_args[2]
        elif entity == 'artwork':
            if len(positional_args) < 3:
                raise CLIExecutionError('create artwork requires: title, artist_id, storage_id')
            data['artwork_ttl'] = positional_args[0]
            data['artist_id'] = positional_args[1]
            data['storage_id'] = positional_args[2]
            # Artwork ID can be provided in options or auto-generated
            if 'artwork_num' in options:
                data['artwork_num'] = options.pop('artwork_num')
            elif 'id' in options:
                data['artwork_num'] = options.pop('id')
            else:
                # Auto-generate artwork ID (same logic as in app.py)
                import secrets
                import string
                max_attempts = 100
                for _ in range(max_attempts):
                    random_part = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                    artwork_id = f"AW{random_part}"
                    if not self.models['Artwork'].query.get(artwork_id):
                        data['artwork_num'] = artwork_id
                        break
                else:
                    raise CLIExecutionError('Failed to generate unique artwork ID after max attempts')
        elif entity == 'storage':
            if len(positional_args) < 2:
                raise CLIExecutionError('create storage requires: storage_id, location')
            data['storage_id'] = positional_args[0]
            data['storage_loc'] = positional_args[1]
        
        # Add options
        data.update(options)
        
        # Validate fields
        is_valid, error_msg = CLIParser.validate_fields(entity, data)
        if not is_valid:
            raise CLIExecutionError(error_msg)
        
        # Create record
        try:
            record = model(**data)
            
            self.db.session.add(record)
            self.db.session.commit()
            
            created_data = self._serialize_record(record, entity)
            
            # Log to audit log
            if user_id is not None:
                self._log_audit_event(
                    f'cli_create_{entity}',
                    user_id=user_id,
                    email=user_email,
                    details={'entity': entity, 'created_data': created_data}
                )
            
            return {
                'success': True,
                'output': f'Successfully created {entity} {created_data[entity_info["id_field"]]}',
                'data': created_data,
                'requires_confirmation': False
            }
        except IntegrityError as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Failed to create {entity}: {str(e)}')
        except Exception as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Failed to create {entity}: {str(e)}')
    
    def _execute_update(self, entity: str, entity_id: str, options: Dict[str, Any], user_id: int = None, user_email: str = None) -> Dict[str, Any]:
        """Execute update command."""
        model = self._get_model(entity)
        record = model.query.get(entity_id)
        
        if not record:
            raise CLIExecutionError(f'{entity.capitalize()} with ID {entity_id} not found')
        
        # Validate fields
        is_valid, error_msg = CLIParser.validate_fields(entity, options)
        if not is_valid:
            raise CLIExecutionError(error_msg)
        
        # Update fields
        changes = {}
        for key, value in options.items():
            if hasattr(record, key):
                old_value = getattr(record, key)
                if old_value != value:
                    # Handle date conversion
                    if key == 'date_created' and isinstance(value, str):
                        try:
                            value = datetime.fromisoformat(value.replace('Z', '+00:00')).date()
                        except ValueError:
                            raise CLIExecutionError(f'Invalid date format for {key}: {value}')
                    
                    changes[key] = {'old': old_value, 'new': value}
                    setattr(record, key, value)
        
        if not changes:
            return {
                'success': True,
                'output': f'No changes detected for {entity} {entity_id}',
                'data': self._serialize_record(record, entity),
                'requires_confirmation': False
            }
        
        try:
            self.db.session.commit()
            
            updated_data = self._serialize_record(record, entity)
            
            # Log to audit log
            if user_id is not None:
                self._log_audit_event(
                    f'cli_update_{entity}',
                    user_id=user_id,
                    email=user_email,
                    details={'entity': entity, 'entity_id': entity_id, 'changes': changes, 'updated_data': updated_data}
                )
            
            return {
                'success': True,
                'output': f'Successfully updated {entity} {entity_id}',
                'data': {'updated': updated_data, 'changes': changes},
                'requires_confirmation': False
            }
        except IntegrityError as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Failed to update {entity}: {str(e)}')
        except Exception as e:
            self.db.session.rollback()
            raise CLIExecutionError(f'Failed to update {entity}: {str(e)}')
    
    def _execute_delete_preview(self, entity: str, entity_id: str) -> Dict[str, Any]:
        """Get preview of what will be deleted (for confirmation)."""
        model = self._get_model(entity)
        record = model.query.get(entity_id)
        
        if not record:
            raise CLIExecutionError(f'{entity.capitalize()} with ID {entity_id} not found')
        
        record_data = self._serialize_record(record, entity)
        
        return {
            'success': True,
            'output': f'Preview: {entity} {entity_id} will be deleted',
            'data': {'to_delete': record_data},
            'requires_confirmation': True
        }
    
    def _execute_start_deletion_scheduler(self) -> Dict[str, Any]:
        """Start the deletion scheduler."""
        from app import start_deletion_scheduler
        try:
            start_result = start_deletion_scheduler()  # your existing function
            return {
                "success": True,
                "output": start_result if isinstance(result, str) else "Deletion Scheduler started/skipped",
                "data": {"scheduler": str(scheduler)} if scheduler else None,
                "requires_confirmation": False
            }
        except Exception as e:
            return {
                "success": False,
                "output": f"Failed to start scheduler: {str(e)}",
                "data": None,
                "requires_confirmation": False
            }

    def _execute_stop_deletion_scheduler(self) -> Dict[str, Any]:
        """Stop the deletion scheduler."""
        from app import stop_deletion_scheduler
        try:
            stop_result = stop_deletion_scheduler()  # your existing function
            return {
                "success": True,
                "output": stop_result if isinstance(result, str) else "Deletion Scheduler stopped/skipped",
                "data": None,
                "requires_confirmation": False
            }
        except Exception as e:
            return {
                "success": False,
                "output": f"Failed to stop scheduler: {str(e)}",
                "data": None,
                "requires_confirmation": False
            }

    def _get_model(self, entity: str):
        """Get model class for entity."""
        model_map = {
            'artist': self.models['Artist'],
            'artwork': self.models['Artwork'],
            'storage': self.models['Storage'],
            'photo': self.models['ArtworkPhoto'],
            'user': self.models['User']
        }
        
        if entity not in model_map:
            raise CLIExecutionError(f'Unknown entity: {entity}')
        
        return model_map[entity]
    
    def _serialize_record(self, record, entity: str) -> Dict[str, Any]:
        """Serialize a database record to dictionary.
        
        Args:
            record: Database record object
            entity: Entity type name
            
        Returns:
            Dictionary representation of record
        """
        data = {}
        entity_info = CLIParser.ENTITIES[entity]
        
        for field in entity_info['fields']:
            if hasattr(record, field):
                value = getattr(record, field)
                # Handle date/datetime serialization
                if isinstance(value, (date, datetime)):
                    data[field] = value.isoformat()
                else:
                    data[field] = value
        
        return data
    
    def _log_audit_event(self, event_type: str, user_id: int = None, email: str = None, details: Dict[str, Any] = None):
        """Log audit event for CLI operations.
        
        Args:
            event_type: Type of event
            user_id: User ID
            email: User email
            details: Additional details
        """
        try:
            from models import init_models
            _, _, AuditLog = init_models(self.db)
            
            ip_address = get_remote_address() if hasattr(request, 'remote_addr') else 'unknown'
            user_agent = request.headers.get('User-Agent', '') if hasattr(request, 'headers') else 'CLI'
            details_json = json.dumps(details) if details else None
            
            audit_log = AuditLog(
                event_type=event_type,
                user_id=user_id,
                email=email,
                ip_address=ip_address,
                user_agent=user_agent,
                details=details_json,
                created_at=datetime.now(timezone.utc)
            )
            
            self.db.session.add(audit_log)
            self.db.session.commit()
        except Exception as e:
            # Silently fail audit logging to prevent breaking CLI flow
            current_app.logger.warning(f'Failed to log audit event: {str(e)}')
            self.db.session.rollback()

