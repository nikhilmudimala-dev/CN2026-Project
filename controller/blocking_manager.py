from itertools import count
import time


class BlockingManager:

    BLOCKING_RULES = {
        "R1_SYN_RATE",
        "R2_CONNECTION_BURST"
    }

    BLOCK_PRIORITY = 30000

    def __init__(
        self,
        offender_manager,
        ban_calculator,
        event_callback=None,
        database=None
    ):

        self.offender_manager = offender_manager
        self.ban_calculator = ban_calculator
        self.event_callback = event_callback
        self.database = database

        self.active_bans = {}
        self.cookie_counter = count(1)

        # Recover previously saved bans from SQLite.
        if self.database is not None:
            self._load_saved_bans()

    def _load_saved_bans(self):

        saved_bans = self.database.get_active_bans()

        for ban in saved_bans:

            self.active_bans[ban["source_ip"]] = {
                **ban,
                "duration_seconds": (
                    ban["expiry_time"] - ban["start_time"]
                ),
                "pending_removals": set()
            }

    def block_host(
        self,
        detection_result,
        datapaths,
        timestamp
    ):

        source_ip = detection_result.source_ip
        rule_id = detection_result.rule_id

        if rule_id not in self.BLOCKING_RULES:
            raise ValueError(
                f"{rule_id} is not allowed to block hosts"
            )

        # Do not extend an existing ban.
        if source_ip in self.active_bans:

            event = {
                "event": "ALREADY_BLOCKED",
                "source_ip": source_ip,
                "rule_id": rule_id,
                "message": (
                    "Host is already blocked. "
                    "Existing ban will not be extended."
                )
            }

            self._record_event(event)
            return event

        datapaths = list(datapaths)

        if not datapaths:
            return {
                "event": "BLOCK_FAILED",
                "source_ip": source_ip,
                "reason": "No connected switches available"
            }

        # Determine the offence count.
        if self.database is not None:

            offence_count = (
                self.database.count_recent_incidents(
                    source_ip,
                    timestamp,
                    self.offender_manager.history_window_seconds
                ) + 1
            )

            # Keep the in-memory history updated too.
            self.offender_manager.register_incident(
                source_ip,
                rule_id,
                timestamp
            )

        else:

            offence_count = (
                self.offender_manager.register_incident(
                    source_ip,
                    rule_id,
                    timestamp
                )
            )

        # Calculate the ban duration.
        duration = self.ban_calculator.calculate(
            detection_result.severity,
            offence_count
        )

        cookie = (0xB10C << 32) | next(self.cookie_counter)

        expiry_time = timestamp + duration

        ban = {
            "source_ip": source_ip,
            "rule_id": rule_id,
            "severity": detection_result.severity,
            "offence_count": offence_count,
            "duration_seconds": duration,
            "ban_duration_seconds": duration,
            "start_time": timestamp,
            "expiry_time": expiry_time,
            "cookie": cookie,
            "pending_removals": {
                datapath.id for datapath in datapaths
            }
        }

        # Persist the incident and ban.
        if self.database is not None:

            self.database.insert_blocking_incident({
                "source_ip": source_ip,
                "rule_id": rule_id,
                "severity": detection_result.severity,
                "offence_count": offence_count,
                "ban_duration_seconds": duration,
                "timestamp": timestamp
            })

            self.database.insert_active_ban(ban)

        # Install the drop rule on every connected switch.
        for datapath in datapaths:

            self._install_drop_rule(
                datapath,
                source_ip,
                duration,
                cookie
            )

        self.active_bans[source_ip] = ban

        event = {
            "event": "HOST_BLOCKED",
            "source_ip": source_ip,
            "rule_id": rule_id,
            "severity": detection_result.severity,
            "offence_count": offence_count,
            "duration_seconds": duration,
            "start_time": timestamp,
            "expiry_time": expiry_time,
            "cookie": cookie
        }

        self._record_event(event)

        return event

    def _install_drop_rule(
        self,
        datapath,
        source_ip,
        duration,
        cookie
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=source_ip
        )

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            table_id=0,
            command=ofproto.OFPFC_ADD,
            idle_timeout=0,
            hard_timeout=max(1, int(duration)),
            priority=self.BLOCK_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM,
            match=match,
            instructions=[]
        )

        datapath.send_msg(flow_mod)

    def restore_active_bans(self, datapaths, current_time=None):

        if current_time is None:
            current_time = time.time()

        datapaths = list(datapaths)
        restored = []

        for source_ip, ban in list(self.active_bans.items()):

            remaining = ban["expiry_time"] - current_time

            # Remove bans that have already expired.
            if remaining <= 0:

                del self.active_bans[source_ip]

                if self.database is not None:
                    self.database.remove_active_ban(source_ip)

                continue

            if not datapaths:
                continue

            ban["pending_removals"] = {
                datapath.id for datapath in datapaths
            }

            # Reinstall the remaining ban duration.
            for datapath in datapaths:

                self._install_drop_rule(
                    datapath,
                    source_ip,
                    remaining,
                    ban["cookie"]
                )

            restored.append(source_ip)

        return restored

    def handle_flow_removed(self, datapath_id, cookie):

        source_ip = None

        for ip, ban in self.active_bans.items():

            if ban["cookie"] == cookie:
                source_ip = ip
                break

        if source_ip is None:
            return None

        ban = self.active_bans[source_ip]

        ban["pending_removals"].discard(datapath_id)

        # Wait for all switches to report removal.
        if ban["pending_removals"]:
            return None

        del self.active_bans[source_ip]

        if self.database is not None:
            self.database.remove_active_ban(source_ip)

        event = {
            "event": "BAN_EXPIRED",
            "source_ip": source_ip,
            "rule_id": ban["rule_id"],
            "message": "Temporary blocking period has ended"
        }

        self._record_event(event)

        return event

    def is_blocked(self, source_ip):

        return source_ip in self.active_bans

    def get_active_bans(self):

        return list(self.active_bans.values())

    def _record_event(self, event):

        if self.event_callback is not None:
            self.event_callback(event)
