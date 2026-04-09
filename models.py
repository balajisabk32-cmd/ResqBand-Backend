from enum import Enum
from dataclasses import dataclass
from typing import Dict, Any, List
from pydantic import BaseModel
from datetime import datetime


class AlertState(str, Enum):
    NORMAL = "NORMAL"
    SOFT_ALERT = "SOFT_ALERT"
    ESCALATED = "ESCALATED"
    EMERGENCY = "EMERGENCY"


class TelemetryPacket(BaseModel):
    bpm: float
    spo2: float
    motion_label: str
    timestamp: float
    session_id: str = "default"


class TelemetryResult(BaseModel):
    packet: TelemetryPacket
    safety_score: float
    risk_level: str
    alert_state: AlertState
    stale_data_override: bool


@dataclass
class SafetySentinelSession:
    model: 'SafetySentinelModel'
    history: List[TelemetryResult] = None

    def __post_init__(self):
        if self.history is None:
            self.history = []


class SafetySentinelModel:
    def __init__(self):
        self.history: List[float] = []
        self.window_size = 10
        self.alert_state = AlertState.NORMAL
        self.last_timestamp = None
        self.consecutive_critical = 0

    def calculate_safety_score(self, packet: TelemetryPacket) -> float:
        bpm = packet.bpm
        spo2 = packet.spo2
        motion = packet.motion_label

        bpm_score = max(0, min(100, 100 - abs(bpm - 72) * 2))
        spo2_score = max(0, min(100, (spo2 - 85) * 5))
        motion_scores = {"Stable": 95, "Unstable": 60, "Fall": 20}
        motion_score = motion_scores.get(motion, 50)

        vital_score = bpm_score * 0.4 + spo2_score * 0.6
        trend_modifier = 0
        if len(self.history) >= 3:
            trend_score = sum(self.history[-3:]) / 3
            trend_modifier = max(-30, min(20, trend_score - 50))

        safety_score = vital_score * 0.7 + motion_score * 0.2 + 15 + trend_modifier * 0.1
        return max(0, min(100, safety_score))

    def determine_risk_level(self, score: float) -> str:
        if score >= 70: return "LOW"
        elif score >= 50: return "MEDIUM"
        elif score >= 30: return "HIGH"
        return "CRITICAL"

    def update_alert_state(self, score: float) -> AlertState:
        if score < 30:
            self.consecutive_critical += 1
        else:
            self.consecutive_critical = 0

        if self.consecutive_critical >= 3 and self.alert_state != AlertState.EMERGENCY:
            if self.alert_state == AlertState.NORMAL:
                self.alert_state = AlertState.SOFT_ALERT
            elif self.alert_state == AlertState.SOFT_ALERT:
                self.alert_state = AlertState.ESCALATED
            elif self.alert_state == AlertState.ESCALATED:
                self.alert_state = AlertState.EMERGENCY
        elif self.consecutive_critical == 0 and self.alert_state != AlertState.NORMAL:
            if self.alert_state == AlertState.EMERGENCY and len(self.history) >= 5:
                recent_avg = sum(self.history[-5:]) / 5
                # Simplified recovery for backend
                if recent_avg >= 70:
                    self.alert_state = AlertState.NORMAL
            elif self.alert_state == AlertState.ESCALATED:
                self.alert_state = AlertState.SOFT_ALERT
            elif self.alert_state == AlertState.SOFT_ALERT:
                self.alert_state = AlertState.NORMAL

        return self.alert_state

    def process_telemetry(self, packet: TelemetryPacket) -> TelemetryResult:
        stale_override = False
        if self.last_timestamp is not None:
            time_diff = packet.timestamp - self.last_timestamp
            if time_diff < -10.0:
                stale_override = True

        self.last_timestamp = packet.timestamp

        if stale_override:
            safety_score = 5.0
            risk_level = "CRITICAL"
            self.consecutive_critical += 1
        else:
            safety_score = self.calculate_safety_score(packet)
            risk_level = self.determine_risk_level(safety_score)

        self.history.append(safety_score)
        if len(self.history) > self.window_size:
            self.history.pop(0)

        alert_state = self.update_alert_state(safety_score)

        return TelemetryResult(
            packet=packet,
            safety_score=safety_score,
            risk_level=risk_level,
            alert_state=alert_state,
            stale_data_override=stale_override
        )
