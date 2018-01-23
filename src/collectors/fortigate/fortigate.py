# coding=utf-8

"""
A collector for Fortinet Fortigate 

#### Dependencies

 * fortiosapi (on pypi)

#### Customizing a collector

Diamond collectors run within the diamond process and collect metrics that can
be published to a graphite server.

Collectors are subclasses of diamond.collector.Collector. In their simplest
form, they need to implement a single method called "collect".

    import diamond.collector

    class FortigateCollector(diamond.collector.Collector):

        def collect(self):

            # Set Metric Path. By default it will be the collector's name
            # (servers.hostname.FortigateCollector.my.example.metric)
            self.config.update({
                'path':     'example',
            })

            # Set Metric Name
            metric_name = "my.example.metric"

            # Set Metric Value
            metric_value = 42

            # Publish Metric
            self.publish(metric_name, metric_value)

For testing collectors, create a directory (example below for /tmp/diamond)
containing your new collector(s), their .conf files, and a copy of diamond.conf
with the following options in diamond.conf:

    [server]

    user = ecuser
    group = ecuser

    handlers = diamond.handler.archive.ArchiveHandler
    handlers_config_path = /tmp/diamond/handlers/
    collectors_path = /tmp/diamond/collectors/
    collectors_config_path = /tmp/diamond/collectors/

    collectors_reload_interval = 3600

    [handlers]

    [[default]]

    [[ArchiveHandler]]
    log_file = /dev/stdout

    [collectors]
    [[default]]

and then run diamond in foreground mode:

    # diamond -f -l --skip-pidfile -c /tmp/diamond/diamond.conf

Diamond supports dynamic addition of collectors. Its configured to scan for new
collectors on a regular interval (configured in diamond.cfg).
If diamond detects a new collector, or that a collectors module has changed
(based on the file's mtime), it will be reloaded.

Diamond looks for collectors in /usr/lib/diamond/collectors/ (on Ubuntu). By
default diamond will invoke the *collect* method every 60 seconds.

Diamond collectors that require a separate configuration file should place a
.cfg file in /etc/diamond/collectors/.
The configuration file name should match the name of the diamond collector
class.  For example, a collector called
*FortigateCollector.FortigateCollector* could have its configuration file placed in
/etc/diamond/collectors/FortigateCollector.cfg.

"""

import logging

import diamond.collector

try:
    from fortiosapi import FortiOSAPI
    fortiosapi = "present"
    # define a variable to avoid stacktraces
except ImportError:
    fortiosapi = None
formatter = logging.Formatter(
    '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
logger = logging.getLogger('fortiosapi')
hdlr = logging.FileHandler('fortigatecollector.log')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

fgt = FortiOSAPI()
fgt.debug('on')


# TODO https://diamond.readthedocs.io/en/latest/collectors/SNMPInterfaceCollector/ get inspired and create a list of fortigate in the conf
class FortigateCollector(diamond.collector.Collector):

    def get_default_config_help(self):
        config_help = super(FortigateCollector, self).get_default_config_help()
        config_help.update({
            'hostname': 'Hostname or IP to collect from',
            'user': 'Username',
            'password': 'Password',
            'https': 'True or False if using http or https (http for eval)',
            'vdom': ''
        })
        return config_help

    def get_default_config(self):
        """
        Returns the default collector settings
        """
        config = super(FortigateCollector, self).get_default_config()
        config.update({
            'user':     'admin',
            'https': 'true',
            'vdom': 'root',
            'password' : ''
        })
        return config

    def __init__(self, *args, **kwargs):
        super(FortigateCollector, self).__init__(*args, **kwargs)
        if fortiosapi is None:
            self.log.error("Unable to import fortiosapi python module")
            exit(2)
        if self.config['https'] == 'false':
            fgt.https('off')
        else:
            fgt.https('on')
        fgt.login(self.config['hostname'], self.config['user'], self.config['password'])
        # Log
        self.log.info("Login successfull for : %s", self.config['hostname'])


    def collect(self):
        """
        Overrides the Collector.collect method
        """

        metrics = fgt.monitor('system','vdom-resource', mkey='select', vdom=self.config['vdom'])['results']

        self.publish("cpu", metrics['cpu'])
        self.publish("memory", metrics['memory'])
        self.publish("sessions", metrics['session']['current_usage'])

