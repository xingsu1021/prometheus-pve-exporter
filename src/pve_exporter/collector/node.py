"""
Prometheus collecters for Proxmox VE cluster.
"""
# pylint: disable=too-few-public-methods

import logging
import itertools

from prometheus_client.core import GaugeMetricFamily


class NodeConfigCollector:
    """
    Collects Proxmox VE VM information directly from config, i.e. boot, name, onboot, etc.
    For manual test: "pvesh get /nodes/<node>/<type>/<vmid>/config"

    # HELP pve_onboot_status Proxmox vm config onboot value
    # TYPE pve_onboot_status gauge
    pve_onboot_status{id="qemu/113",node="XXXX",type="qemu"} 1.0
    """

    def __init__(self, pve):
        self._pve = pve
        self._log = logging.getLogger(__name__)

    def collect(self):  # pylint: disable=missing-docstring
        metrics = {
            'onboot': GaugeMetricFamily(
                'pve_onboot_status',
                'Proxmox vm config onboot value',
                labels=['id', 'node', 'type']),
        }

        node = None
        for entry in self._pve.cluster.status.get():
            if entry['type'] == 'node' and entry['local']:
                node = entry['name']
                break

        # Scrape qemu config
        vmtype = 'qemu'
        for vmdata in self._pve.nodes(node).qemu.get():
            config = self._pve.nodes(node).qemu(
                vmdata['vmid']).config.get().items()
            for key, metric_value in config:
                label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype]
                if key in metrics:
                    metrics[key].add_metric(label_values, metric_value)

        # Scrape LXC config
        vmtype = 'lxc'
        for vmdata in self._pve.nodes(node).lxc.get():
            config = self._pve.nodes(node).lxc(
                vmdata['vmid']).config.get().items()
            for key, metric_value in config:
                label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype]
                if key in metrics:
                    metrics[key].add_metric(label_values, metric_value)

        return metrics.values()

class NodeReplicationCollector:
    """
    Collects Proxmox VE Replication information directly from status, i.e. replication duration,
    last_sync, last_try, next_sync, fail_count.
    For manual test: "pvesh get /nodes/<node>/replication/<id>/status"
    """

    def __init__(self, pve):
        self._pve = pve

    def collect(self): # pylint: disable=missing-docstring

        info_metrics = {
            'info': GaugeMetricFamily(
            'pve_replication_info',
            'Proxmox vm replication info',
            labels=['id', 'type', 'source', 'target', 'guest'])
        }

        metrics = {
            'duration': GaugeMetricFamily(
                'pve_replication_duration_seconds',
                'Proxmox vm replication duration',
                labels=['id']),
            'last_sync': GaugeMetricFamily(
                'pve_replication_last_sync_timestamp_seconds',
                'Proxmox vm replication last_sync',
                labels=['id']),
            'last_try': GaugeMetricFamily(
                'pve_replication_last_try_timestamp_seconds',
                'Proxmox vm replication last_try',
                labels=['id']),
            'next_sync': GaugeMetricFamily(
                'pve_replication_next_sync_timestamp_seconds',
                'Proxmox vm replication next_sync',
                labels=['id']),
            'fail_count': GaugeMetricFamily(
                'pve_replication_failed_syncs',
                'Proxmox vm replication fail_count',
                labels=['id']),
        }

        node = None
        for entry in self._pve.cluster.status.get():
            if entry['type'] == 'node' and entry['local']:
                node = entry['name']
                break

        for jobdata in self._pve.nodes(node).replication.get():
            # Add info metric
            label_values = [
                str(jobdata['id']),
                str(jobdata['type']),
                f"node/{jobdata['source']}",
                f"node/{jobdata['target']}",
                f"{jobdata['vmtype']}/{jobdata['guest']}",
            ]
            info_metrics['info'].add_metric(label_values, 1)

            # Add metrics
            label_values = [str(jobdata['id'])]
            status = self._pve.nodes(node).replication(jobdata['id']).status.get()
            for key, metric_value in status.items():
                if key in metrics:
                    metrics[key].add_metric(label_values, metric_value)

        return itertools.chain(metrics.values(), info_metrics.values())


class NodeAgentCollector:
    """
    For manual test: "pvesh get /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"

    """

    def __init__(self, pve):
        self._pve = pve
        self._log = logging.getLogger(__name__)

    def collect(self):  # pylint: disable=missing-docstring
        metrics = {
            'network': GaugeMetricFamily(
                'pve_agent_network',
                'Proxmox vm agent Network value',
                labels=['id', 'node', 'type', 'agent_status','interface_name','interface_ip']),
        }

        node = None
        for entry in self._pve.cluster.status.get():
            if entry['type'] == 'node' and entry['local']:
                node = entry['name']
                break

        # Scrape qemu config
        vmtype = 'qemu'
        for vmdata in self._pve.nodes(node).qemu.get():

            if vmdata['status']=='running':
                try:
                    agent = self._pve.nodes(node).qemu(
                        vmdata['vmid']).agent.get('network-get-interfaces')
                    
                    #[{'name': 'ens18', 'ip-addresses': ['172.25.135.30']}]
                    result = [
                        {
                            'name': entry['name'],
                            'ip-addresses': [ip['ip-address'] for ip in entry['ip-addresses'] if ip['ip-address-type'] == 'ipv4']
                        }
                        for entry in agent['result']
                        if not any(substring in entry['name'] for substring in ['lo', 'veth', 'docker', 'cni', 'flannel', 'br-','kube','cali', 'tunl','as0', 'Loopback','isatap','Tunne'])
                    ]
                    #print("result---->",result)
                    interface_name = ', '.join([entry['name'] for entry in result])
                    #print('interface_name--->',interface_name)
                    interface_ip = ', '.join([entry['ip-addresses'][0] for entry in result])
                    #print('interface_ip--->',interface_ip)
                    label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype, "1", interface_name, interface_ip]
                    #print("label_values=-->",label_values)
                    metrics['network'].add_metric(label_values, 1)

                    # for data in agent['result']:
                        
                    #     network_name = data['name']
                    #     if "lo" not in network_name and "veth" not in network_name and \
                    #         "flannel" not in network_name and "cni" not in network_name and \
                    #         "docker" not in network_name:
                    #         print("name--->%s, ip--->%s" % (data['name'],data['ip-addresses']))
                    #     # for key, metric_value in data:
                    #     #     print("key--->",key)
                    #     #     print("metric_value--->",metric_value)
                            
                    #         # if key in metrics:
                    #         #     metrics[key].add_metric(label_values, metric_value)
                    #         ipv4_addresses = [entry['ip-address'] for entry in data if entry['ip-address-type'] == 'ipv4']
                    #         label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype, "1", data['name'], ipv4_addresses]
                    #         metrics['network'].add_metric(label_values, 1)
                except:
                    #print("error--->",vmdata['name'])
                    #metrics['agent_status'].add_metric(label_values, 0)
                    label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype, "0", "0","0"]
                    metrics['network'].add_metric(label_values, 0)

        # Scrape LXC config
        # vmtype = 'lxc'
        # for vmdata in self._pve.nodes(node).lxc.get():
        #     config = self._pve.nodes(node).lxc(
        #         vmdata['vmid']).config.get().items()
        #     for key, metric_value in config:
        #         label_values = [f"{vmtype}/{vmdata['vmid']}", node, vmtype]
        #         if key in metrics:
        #             metrics[key].add_metric(label_values, metric_value)
        #print("metrics--->",metrics)
        return metrics.values()