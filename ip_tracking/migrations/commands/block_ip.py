# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand, CommandError
from ip_tracking.models import BlockedIP
from django.core.validators import validate_ipv46_address
from django.core.exceptions import ValidationError

class Command(BaseCommand):
    help = 'Adds an IP address to the blacklist (BlockedIP model).'

    def add_arguments(self, parser):
        parser.add_argument(
            'ip_address', 
            type=str, 
            help='The IPv4 or IPv6 address to block.'
        )
        parser.add_argument(
            '--reason', 
            type=str, 
            default='Manually blocked by admin', 
            help='Optional reason for blocking the IP.'
        )

    def handle(self, *args, **options):
        ip_address = options['ip_address']
        reason = options['reason']
        
        try:
            validate_ipv46_address(ip_address)
        except ValidationError:
            raise CommandError(f'"{ip_address}" is not a valid IPv4 or IPv6 address.')

        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={'reason': reason}
            )
            
            if created:
                self.stdout.write(self.style.SUCCESS(f'Successfully blocked IP: {ip_address} (Reason: {reason})'))
            else:
                blocked_ip.reason = reason
                blocked_ip.save()
                self.stdout.write(self.style.WARNING(f'IP {ip_address} was already blocked. Updated reason to: {reason}'))

        except Exception as e:
            raise CommandError(f'Database error while blocking IP {ip_address}: {e}')