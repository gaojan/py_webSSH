import logging
import os.path
import ssl
from app.ssh.policy import (
    load_host_keys, get_policy_class, check_policy_setting
)
from app.utils import to_ip_address, parse_origin_from_url
from app.settings import base_dir, max_body_size


def get_app_settings(options):
    settings = dict(
        template_path=os.path.join(base_dir, 'templates'),
        static_path=os.path.join(base_dir, 'static'),
        websocket_ping_interval=options.wpintvl,
        debug=options.debug,
        xsrf_cookies=options.xsrf,
        origin_policy=get_origin_setting(options)
    )
    return settings


def get_server_settings(options):
    settings = dict(
        xheaders=options.xheaders,
        max_body_size=max_body_size,
        trusted_downstream=get_trusted_downstream(options.tdstream)
    )
    return settings


def get_host_keys_settings(options):
    if not options.hostfile:
        host_keys_filename = os.path.join(base_dir, 'known_hosts')
    else:
        host_keys_filename = options.hostfile
    host_keys = load_host_keys(host_keys_filename)

    if not options.syshostfile:
        filename = os.path.expanduser('~/.ssh/known_hosts')
    else:
        filename = options.syshostfile
    system_host_keys = load_host_keys(filename)

    settings = dict(
        host_keys=host_keys,
        system_host_keys=system_host_keys,
        host_keys_filename=host_keys_filename
    )
    return settings


def get_policy_setting(options, host_keys_settings):
    policy_class = get_policy_class(options.policy)
    logging.info(policy_class.__name__)
    check_policy_setting(policy_class, host_keys_settings)
    return policy_class()


def get_ssl_context(options):
    if not options.certfile and not options.keyfile:
        return None
    elif not options.certfile:
        raise ValueError('certfile is not provided')
    elif not options.keyfile:
        raise ValueError('keyfile is not provided')
    elif not os.path.isfile(options.certfile):
        raise ValueError('File {!r} does not exist'.format(options.certfile))
    elif not os.path.isfile(options.keyfile):
        raise ValueError('File {!r} does not exist'.format(options.keyfile))
    else:
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(options.certfile, options.keyfile)
        return ssl_ctx


def get_trusted_downstream(tdstream):
    result = set()
    for ip in tdstream.split(','):
        ip = ip.strip()
        if ip:
            to_ip_address(ip)
            result.add(ip)
    return result


def get_origin_setting(options):
    if options.origin == '*':
        if not options.debug:
            raise ValueError(
                'Wildcard origin policy is only allowed in debug mode.'
            )
        else:
            return '*'

    origin = options.origin.lower()
    if origin in ['same', 'primary']:
        return origin

    origins = set()
    for url in origin.split(','):
        orig = parse_origin_from_url(url)
        if orig:
            origins.add(orig)

    if not origins:
        raise ValueError('Empty origin list')

    return origins
