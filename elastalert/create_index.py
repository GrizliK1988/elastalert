#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import argparse
import getpass
import os
import time

import elasticsearch.helpers
import yaml
from auth import Auth
from elasticsearch import RequestsHttpConnection
from elasticsearch.client import Elasticsearch
from elasticsearch.client import IndicesClient
from envparse import Env

env = Env(ES_USE_SSL=bool)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=os.environ.get('ES_HOST', None), help='Elasticsearch host')
    parser.add_argument('--port', default=os.environ.get('ES_PORT', None), type=int, help='Elasticsearch port')
    parser.add_argument('--username', default=os.environ.get('ES_USERNAME', None), help='Elasticsearch username')
    parser.add_argument('--password', default=os.environ.get('ES_PASSWORD', None), help='Elasticsearch password')
    parser.add_argument('--url-prefix', help='Elasticsearch URL prefix')
    parser.add_argument('--no-auth', action='store_const', const=True, help='Suppress prompt for basic auth')
    parser.add_argument('--ssl', action='store_true', default=env('ES_USE_SSL', None), help='Use TLS')
    parser.add_argument('--no-ssl', dest='ssl', action='store_false', help='Do not use TLS')
    parser.add_argument('--verify-certs', action='store_true', default=None, help='Verify TLS certificates')
    parser.add_argument('--no-verify-certs', dest='verify_certs', action='store_false',
                        help='Do not verify TLS certificates')
    parser.add_argument('--index-prefix', help='Prefix of index names to create')
    parser.add_argument('--old-index-prefix', help='Prefix of index names to copy')
    parser.add_argument('--send_get_body_as', default='GET',
                        help='Method for querying Elasticsearch - POST, GET or source')
    parser.add_argument(
        '--boto-profile',
        default=None,
        dest='profile',
        help='DEPRECATED: (use --profile) Boto profile to use for signing requests')
    parser.add_argument(
        '--profile',
        default=None,
        help='AWS profile to use for signing requests. Optionally use the AWS_DEFAULT_PROFILE environment variable')
    parser.add_argument(
        '--aws-region',
        default=None,
        help='AWS Region to use for signing requests. Optionally use the AWS_DEFAULT_REGION environment variable')
    parser.add_argument('--timeout', default=60, help='Elasticsearch request timeout')
    parser.add_argument('--config', default='config.yaml', help='Global config file (default: config.yaml)')
    args = parser.parse_args()

    if os.path.isfile('config.yaml'):
        filename = 'config.yaml'
    elif os.path.isfile(args.config):
        filename = args.config
    else:
        filename = ''

    if filename:
        with open(filename) as config_file:
            data = yaml.load(config_file)
        host = args.host if args.host else data.get('es_host')
        port = args.port if args.port else data.get('es_port')
        username = args.username if args.username else data.get('es_username')
        password = args.password if args.password else data.get('es_password')
        url_prefix = args.url_prefix if args.url_prefix is not None else data.get('es_url_prefix', '')
        use_ssl = args.ssl if args.ssl is not None else data.get('use_ssl')
        verify_certs = args.verify_certs if args.verify_certs is not None else data.get('verify_certs') is not False
        aws_region = data.get('aws_region', None)
        send_get_body_as = data.get('send_get_body_as', 'GET')
        ca_certs = data.get('ca_certs')
        client_cert = data.get('client_cert')
        client_key = data.get('client_key')
    else:
        username = args.username if args.username else None
        password = args.password if args.password else None
        aws_region = args.aws_region
        host = args.host if args.host else raw_input('Enter Elasticsearch host: ')
        port = args.port if args.port else int(raw_input('Enter Elasticsearch port: '))
        use_ssl = (args.ssl if args.ssl is not None
        else raw_input('Use SSL? t/f: ').lower() in ('t', 'true'))
        if use_ssl:
            verify_certs = (args.verify_certs if args.verify_certs is not None
            else raw_input('Verify TLS certificates? t/f: ').lower() not in ('f', 'false'))
        else:
            verify_certs = True
        if args.no_auth is None and username is None:
            username = raw_input('Enter optional basic-auth username (or leave blank): ')
            password = getpass.getpass('Enter optional basic-auth password (or leave blank): ')
        url_prefix = (args.url_prefix if args.url_prefix is not None
        else raw_input('Enter optional Elasticsearch URL prefix (prepends a string to the URL of every request): '))
        send_get_body_as = args.send_get_body_as
        ca_certs = None
        client_cert = None
        client_key = None

    timeout = args.timeout
    auth = Auth()
    http_auth = auth(host=host,
                     username=username,
                     password=password,
                     aws_region=aws_region,
                     profile_name=args.profile)
    es = Elasticsearch(
        host=host,
        port=port,
        timeout=timeout,
        use_ssl=use_ssl,
        verify_certs=verify_certs,
        connection_class=RequestsHttpConnection,
        http_auth=http_auth,
        url_prefix=url_prefix,
        send_get_body_as=send_get_body_as,
        client_cert=client_cert,
        ca_certs=ca_certs,
        client_key=client_key)

    silence_mapping = {'doc': {'properties': {'rule_name': {'type': 'keyword'},
                                              'until': {'type': 'date', 'format': 'dateOptionalTime'},
                                              '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}
    ess_mapping = {'doc': {'properties': {'rule_name': {'type': 'keyword'},
                                          '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}
    es_mapping = {'doc': {'properties': {'rule_name': {'type': 'keyword'},
                                         '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'},
                                         'alert_time': {'format': 'dateOptionalTime', 'type': 'date'},
                                         'match_time': {'format': 'dateOptionalTime', 'type': 'date'},
                                         'match_body': {'enabled': False, 'type': 'object'},
                                         'aggregate_id': {'type': 'keyword'}}}}
    past_mapping = {'doc': {'properties': {'rule_name': {'type': 'keyword'},
                                           'match_body': {'enabled': False, 'type': 'object'},
                                           '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'},
                                           'aggregate_id': {'type': 'keyword'}}}}
    error_mapping = {'doc': {'properties': {'data': {'type': 'object', 'enabled': False},
                                            '@timestamp': {'format': 'dateOptionalTime', 'type': 'date'}}}}

    index_prefix = args.index_prefix if args.index_prefix is not None else raw_input(
        'New index names prefix? (Default elastalert_) ')
    if not index_prefix:
        index_prefix = 'elastalert_'

    old_index_prefix = (args.old_index_prefix if args.old_index_prefix is not None
    else raw_input('Name of existing index to copy? (Default None) '))
    if not old_index_prefix:
        old_index_prefix = ''

    indexMappings = [
        {"index": 'elastalert', 'mapping': es_mapping},
        {"index": 'elastalert_status', 'mapping': ess_mapping},
        {"index": 'silence', 'mapping': silence_mapping},
        {"index": 'elastalert_error', 'mapping': error_mapping},
        {"index": 'past_elastalert', 'mapping': past_mapping},
    ]

    es_index = IndicesClient(es)
    for indexMapping in indexMappings:
        if es_index.exists(index_prefix + indexMapping['index']):
            print('Index ' + index_prefix + indexMapping['index'] + ' already exists. Skipping index creation.')
            return None

    for indexMapping in indexMappings:
        time.sleep(2)
        es.indices.create(index_prefix + indexMapping['index'])
        es.indices.put_mapping(index=index_prefix + indexMapping['index'], doc_type='doc', body=indexMapping['mapping'])
        print('New index %s created' % (index_prefix + indexMapping['index']))
        if old_index_prefix:
            new_index = index_prefix + indexMapping['index']
            old_index = old_index_prefix + indexMapping['index']
            print("Copying all data from old index '{0}/doc' to new index '{1}/doc'".format(old_index, new_index))
            # Use the defaults for chunk_size, scroll, scan_kwargs, and bulk_kwargs
            elasticsearch.helpers.reindex(es, old_index, new_index)

    print('Done!')


if __name__ == '__main__':
    main()
