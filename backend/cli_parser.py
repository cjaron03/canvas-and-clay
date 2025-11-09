"""CLI command parser for admin console.

Parses and validates CLI commands before execution.
"""
import re
import shlex
from typing import Dict, List, Optional, Tuple, Any


class CLIParseError(Exception):
    """Error raised when CLI command parsing fails."""
    pass


class CLIParser:
    """Parser for CLI commands."""
    
    # Supported entities and their models (singular form)
    ENTITIES = {
        'artist': {
            'id_field': 'artist_id',
            'id_type': 'CHAR(8)',
            'fields': ['artist_id', 'artist_fname', 'artist_lname', 'artist_email', 'artist_site', 'artist_bio', 'artist_phone', 'user_id']
        },
        'artwork': {
            'id_field': 'artwork_num',
            'id_type': 'CHAR(8)',
            'fields': ['artwork_num', 'artwork_ttl', 'artist_id', 'storage_id', 'artwork_medium', 'date_created', 'artwork_size']
        },
        'storage': {
            'id_field': 'storage_id',
            'id_type': 'CHAR(7)',
            'fields': ['storage_id', 'storage_loc', 'storage_type']
        },
        'photo': {
            'id_field': 'photo_id',
            'id_type': 'CHAR(8)',
            'fields': ['photo_id', 'artwork_num', 'filename', 'file_path', 'thumbnail_path', 'file_size', 'mime_type', 'width', 'height', 'uploaded_at', 'uploaded_by', 'is_primary']
        },
        'user': {
            'id_field': 'id',
            'id_type': 'INTEGER',
            'fields': ['id', 'email', 'role', 'is_active', 'created_at']
        }
    }
    
    # Map plural forms to singular
    ENTITY_PLURAL_MAP = {
        'artists': 'artist',
        'artworks': 'artwork',
        'storages': 'storage',
        'photos': 'photo',
        'users': 'user'
    }
    
    @classmethod
    def _normalize_entity(cls, entity: str) -> str:
        """Normalize entity name (plural to singular).
        
        Args:
            entity: Entity name (singular or plural)
            
        Returns:
            Singular entity name
        """
        entity_lower = entity.lower()
        # Check if it's already singular
        if entity_lower in cls.ENTITIES:
            return entity_lower
        # Check if it's plural
        if entity_lower in cls.ENTITY_PLURAL_MAP:
            return cls.ENTITY_PLURAL_MAP[entity_lower]
        # Return as-is if not found (will be caught by validation)
        return entity_lower
    
    # Supported actions
    ACTIONS = {
        'list': {'read_only': True, 'requires_id': False},
        'show': {'read_only': True, 'requires_id': True},
        'create': {'read_only': False, 'requires_id': False},
        'update': {'read_only': False, 'requires_id': True},
        'delete': {'read_only': False, 'requires_id': True},
        'help': {'read_only': True, 'requires_id': False},
        'stats': {'read_only': True, 'requires_id': False}
    }
    
    @classmethod
    def parse(cls, command: str) -> Dict[str, Any]:
        """Parse a CLI command string.
        
        Args:
            command: The command string to parse
            
        Returns:
            Dictionary with parsed command structure:
            {
                'action': str,
                'entity': str or None,
                'entity_id': str or None,
                'options': dict,
                'positional_args': list,
                'is_read_only': bool
            }
            
        Raises:
            CLIParseError: If command is invalid
        """
        if not command or not command.strip():
            raise CLIParseError('Empty command')
        
        command = command.strip()
        
        # Handle help command
        if command.lower() == 'help':
            return {
                'action': 'help',
                'entity': None,
                'entity_id': None,
                'options': {},
                'positional_args': [],
                'is_read_only': True
            }
        
        # Handle stats command
        if command.lower() == 'stats':
            return {
                'action': 'stats',
                'entity': None,
                'entity_id': None,
                'options': {},
                'positional_args': [],
                'is_read_only': True
            }
        
        # Split command into parts using shlex to handle quoted strings
        try:
            parts = shlex.split(command)
        except ValueError as e:
            raise CLIParseError(f'Invalid command syntax: {str(e)}')
        
        if not parts:
            raise CLIParseError('Empty command')
        
        action = parts[0].lower()
        
        # Validate action
        if action not in cls.ACTIONS:
            raise CLIParseError(f'Unknown action: {action}. Available: {", ".join(cls.ACTIONS.keys())}')
        
        action_info = cls.ACTIONS[action]
        is_read_only = action_info['read_only']
        requires_id = action_info['requires_id']
        
        # Parse entity and options
        entity = None
        entity_id = None
        options = {}
        positional_args = []
        
        if action in ['list', 'create']:
            # list artists, create artist ...
            if len(parts) < 2:
                raise CLIParseError(f'Action "{action}" requires an entity (e.g., "{action} artist" or "{action} artists")')
            entity = cls._normalize_entity(parts[1])
            
            if entity not in cls.ENTITIES:
                available = ', '.join(sorted(set(list(cls.ENTITIES.keys()) + list(cls.ENTITY_PLURAL_MAP.keys()))))
                raise CLIParseError(f'Unknown entity: {parts[1]}. Available: {available}')
            
            # Parse options and positional args
            remaining = parts[2:]
            positional_args, options = cls._parse_args(remaining, entity, action)
            
        elif action == 'show':
            # show artwork AW123456
            if len(parts) < 3:
                raise CLIParseError(f'Action "{action}" requires entity and ID (e.g., "{action} artwork AW123456")')
            entity = cls._normalize_entity(parts[1])
            
            if entity not in cls.ENTITIES:
                available = ', '.join(sorted(set(list(cls.ENTITIES.keys()) + list(cls.ENTITY_PLURAL_MAP.keys()))))
                raise CLIParseError(f'Unknown entity: {parts[1]}. Available: {available}')
            
            entity_id = parts[2]
            remaining = parts[3:]
            _, options = cls._parse_args(remaining, entity, action)
            
        elif action in ['update', 'delete']:
            # update artwork AW123456 --title="New Title"
            # delete artwork AW123456
            if len(parts) < 3:
                raise CLIParseError(f'Action "{action}" requires entity and ID (e.g., "{action} artwork AW123456")')
            entity = cls._normalize_entity(parts[1])
            
            if entity not in cls.ENTITIES:
                available = ', '.join(sorted(set(list(cls.ENTITIES.keys()) + list(cls.ENTITY_PLURAL_MAP.keys()))))
                raise CLIParseError(f'Unknown entity: {parts[1]}. Available: {available}')
            
            entity_id = parts[2]
            remaining = parts[3:]
            _, options = cls._parse_args(remaining, entity, action)
        
        return {
            'action': action,
            'entity': entity,
            'entity_id': entity_id,
            'options': options,
            'positional_args': positional_args,
            'is_read_only': is_read_only
        }
    
    @classmethod
    def _parse_args(cls, args: List[str], entity: str, action: str) -> Tuple[List[str], Dict[str, Any]]:
        """Parse positional arguments and options from command args.
        
        Args:
            args: List of argument strings
            entity: Entity name for validation
            action: Action name
            
        Returns:
            Tuple of (positional_args, options_dict)
        """
        positional_args = []
        options = {}
        
        i = 0
        while i < len(args):
            arg = args[i]
            
            if arg.startswith('--'):
                # Option: --key=value or --key value
                key = arg[2:]
                if '=' in key:
                    opt_key, opt_value = key.split('=', 1)
                    options[opt_key] = cls._parse_value(opt_value)
                else:
                    if i + 1 < len(args) and not args[i + 1].startswith('--'):
                        options[key] = cls._parse_value(args[i + 1])
                        i += 1
                    else:
                        options[key] = True  # Boolean flag
            else:
                # Positional argument
                positional_args.append(cls._parse_value(arg))
            
            i += 1
        
        return positional_args, options
    
    @classmethod
    def _parse_value(cls, value: str) -> Any:
        """Parse a value string, handling quotes and types.
        
        Args:
            value: String value to parse
            
        Returns:
            Parsed value (string, int, bool, etc.)
        """
        # Remove quotes if present
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            return value[1:-1]
        
        # Try to parse as boolean
        if value.lower() == 'true':
            return True
        if value.lower() == 'false':
            return False
        
        # Try to parse as integer
        try:
            return int(value)
        except ValueError:
            pass
        
        # Return as string
        return value
    
    @classmethod
    def validate_fields(cls, entity: str, fields: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate field names against entity schema.
        
        Args:
            entity: Entity name
            fields: Dictionary of field names to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if entity not in cls.ENTITIES:
            return False, f'Unknown entity: {entity}'
        
        valid_fields = cls.ENTITIES[entity]['fields']
        invalid_fields = [f for f in fields.keys() if f not in valid_fields]
        
        if invalid_fields:
            return False, f'Invalid fields for {entity}: {", ".join(invalid_fields)}. Valid fields: {", ".join(valid_fields)}'
        
        return True, None
    
    @classmethod
    def get_help(cls) -> Dict[str, Any]:
        """Get help information for all commands.
        
        Returns:
            Dictionary with command help information
        """
        help_info = {
            'commands': [],
            'entities': sorted(set(list(cls.ENTITIES.keys()) + list(cls.ENTITY_PLURAL_MAP.keys()))),
            'actions': list(cls.ACTIONS.keys())
        }
        
        # Add command examples
        examples = [
            {
                'command': 'list artists',
                'description': 'List all artists (plural form accepted)',
                'read_only': True
            },
            {
                'command': 'list artist',
                'description': 'List all artists (singular form also works)',
                'read_only': True
            },
            {
                'command': 'list artworks --artist=TSTART01',
                'description': 'List artworks filtered by artist ID',
                'read_only': True
            },
            {
                'command': 'show artwork AW123456',
                'description': 'Show details of a specific artwork',
                'read_only': True
            },
            {
                'command': 'create artist TSTART01 "John" "Doe" --email="john@example.com"',
                'description': 'Create a new artist',
                'read_only': False
            },
            {
                'command': 'update artwork AW123456 --artwork_ttl="New Title"',
                'description': 'Update artwork fields',
                'read_only': False
            },
            {
                'command': 'delete artwork AW123456',
                'description': 'Delete an artwork (requires double confirmation)',
                'read_only': False
            },
            {
                'command': 'help',
                'description': 'Show this help message',
                'read_only': True
            },
            {
                'command': 'stats',
                'description': 'Show system statistics',
                'read_only': True
            }
        ]
        
        help_info['commands'] = examples
        help_info['entity_fields'] = {entity: cls.ENTITIES[entity]['fields'] for entity in cls.ENTITIES}
        
        return help_info

