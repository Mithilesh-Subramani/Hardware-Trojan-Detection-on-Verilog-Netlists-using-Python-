import re
import json
import math
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional



@dataclass
class Gate:
    name: str
    gate_type: str
    inputs: list[str]
    output: str
    fanout: int = 0

@dataclass
class TrojanReport:
    file: str
    total_gates: int
    suspicious_gates: list[dict]
    triggering_signals: list[str]
    non_triggering_signals: list[str]
    anomaly_score: float
    verdict: str
    details: dict = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)





    GATE_TYPES = {"and", "or", "nand", "nor", "xor", "xnor", "not", "buf",
                  "mux", "dff", "latch", "full_adder", "half_adder"}

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.gates: list[Gate] = []
        self.inputs: list[str] = []
        self.outputs: list[str] = []
        self.wires: list[str] = []
        self.module_name: str = ""

    def parse(self) -> "VerilogParser":
        text = Path(self.filepath).read_text()
        text = self._strip_comments(text)
        self._parse_module(text)
        self._parse_ports(text)
        self._parse_gate_instantiations(text)
        return self

    def _strip_comments(self, text: str) -> str:
        text = re.sub(r'//.*', '', text)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        return text

    def _parse_module(self, text: str):
        m = re.search(r'module\s+(\w+)', text)
        if m:
            self.module_name = m.group(1)

    def _parse_ports(self, text: str):
        for m in re.finditer(r'\binput\b\s+(.*?);', text, re.DOTALL):
            self.inputs += [w.strip() for w in m.group(1).split(',') if w.strip()]
        for m in re.finditer(r'\boutput\b\s+(.*?);', text, re.DOTALL):
            self.outputs += [w.strip() for w in m.group(1).split(',') if w.strip()]
        for m in re.finditer(r'\bwire\b\s+(.*?);', text, re.DOTALL):
            self.wires += [w.strip() for w in m.group(1).split(',') if w.strip()]

    def _parse_gate_instantiations(self, text: str):
        # Pattern: gate_type instance_name ( port_list );
        pattern = re.compile(
            r'(\w+)\s+(\w+)\s*\(\s*(.*?)\s*\)\s*;', re.DOTALL
        )
        for m in pattern.finditer(text):
            gtype = m.group(1).lower()
            if gtype in ("module", "input", "output", "wire", "reg", "endmodule"):
                continue
            gname = m.group(2)
            ports = [p.strip() for p in m.group(3).split(',') if p.strip()]
            if len(ports) < 2:
                continue
            # Convention: first port = output, rest = inputs
            gate = Gate(
                name=gname,
                gate_type=gtype,
                output=ports[0],
                inputs=ports[1:]
            )
            self.gates.append(gate)

    def compute_fanout(self):
        """Count how many gates use each net as input."""
        fanout_map: dict[str, int] = {}
        for g in self.gates:
            for inp in g.inputs:
                fanout_map[inp] = fanout_map.get(inp, 0) + 1
        for g in self.gates:
            g.fanout = fanout_map.get(g.output, 0)
        return fanout_map




    W_LOW_FANOUT   = 0.30
    W_RARE_GATE    = 0.25
    W_ISOLATED     = 0.25
    W_SEQ_ANOMALY  = 0.20

    RARE_GATES = {"xnor", "latch", "full_adder", "half_adder"}
    TRIGGER_GATES = {"and", "nand", "nor"}   # common in trigger logic
    PAYLOAD_GATES = {"xor", "xnor", "mux"}  # common in payload logic

    def __init__(self, parser: VerilogParser, params: Optional[dict] = None):
        self.p = parser
        self.params = params or {}
        self.fanout_threshold = self.params.get("fanout_threshold", 2)
        self.score_threshold  = self.params.get("score_threshold", 0.45)

    def analyze(self) -> TrojanReport:
        fanout_map = self.p.compute_fanout()

        suspicious: list[dict] = []
        triggering_sigs: list[str] = []
        non_triggering_sigs: list[str] = []

        reachable = self._reachable_nets()

        scores = {
            "low_fanout": 0.0,
            "rare_gate": 0.0,
            "isolated": 0.0,
            "seq_anomaly": 0.0,
        }

        for gate in self.p.gates:
            flags = []
            gate_score = 0.0

            # 1. Low-fanout output → potential trigger signal
            fo = fanout_map.get(gate.output, 0)
            if fo <= self.fanout_threshold and gate.output not in self.p.outputs:
                flags.append(f"low_fanout({fo})")
                gate_score += self.W_LOW_FANOUT
                if gate.gate_type in self.TRIGGER_GATES:
                    triggering_sigs.append(gate.output)
                else:
                    non_triggering_sigs.append(gate.output)

          
            if gate.gate_type in self.RARE_GATES:
                flags.append(f"rare_gate_type({gate.gate_type})")
                gate_score += self.W_RARE_GATE

           
            if gate.output not in reachable:
                flags.append("isolated_net")
                gate_score += self.W_ISOLATED


            if gate.gate_type in ("dff", "latch"):
                has_reset = any("rst" in i.lower() or "reset" in i.lower()
                                or "clr" in i.lower() for i in gate.inputs)
                if not has_reset:
                    flags.append("seq_no_reset")
                    gate_score += self.W_SEQ_ANOMALY

            if flags:
                suspicious.append({
                    "gate": gate.name,
                    "type": gate.gate_type,
                    "output_net": gate.output,
                    "flags": flags,
                    "gate_score": round(gate_score, 3),
                })
                for k in scores:
                    for f in flags:
                        if k in f:
                            scores[k] += gate_score

       
        n = max(len(self.p.gates), 1)
        raw = sum(scores.values()) / n
        # Normalise to [0,1] via sigmoid-like curve
        anomaly_score = round(1 / (1 + math.exp(-8 * (raw - 0.2))), 4)

        verdict = self._verdict(anomaly_score, suspicious)

        return TrojanReport(
            file=self.p.filepath,
            total_gates=len(self.p.gates),
            suspicious_gates=suspicious,
            triggering_signals=list(set(triggering_sigs)),
            non_triggering_signals=list(set(non_triggering_sigs)),
            anomaly_score=anomaly_score,
            verdict=verdict,
            details={
                "module": self.p.module_name,
                "inputs": self.p.inputs,
                "outputs": self.p.outputs,
                "component_scores": {k: round(v, 4) for k, v in scores.items()},
                "params_used": {
                    "fanout_threshold": self.fanout_threshold,
                    "score_threshold": self.score_threshold,
                }
            }
        )

    def _reachable_nets(self) -> set[str]:
        
        output_set = set(self.p.outputs)
        net_to_gate = {g.output: g for g in self.p.gates}
        visited = set(output_set)
        queue = list(output_set)
        while queue:
            net = queue.pop()
            g = net_to_gate.get(net)
            if g:
                for inp in g.inputs:
                    if inp not in visited:
                        visited.add(inp)
                        queue.append(inp)
        return visited

    def _verdict(self, score: float, suspicious: list) -> str:
        n_sus = len(suspicious)
        has_trigger_payload = any(
            any(f in fl for f in ("low_fanout", "rare_gate", "isolated"))
            for s in suspicious for fl in [s["flags"]]
        )
        if score >= self.score_threshold and has_trigger_payload:
            return "TROJAN_DETECTED"
        elif score >= self.score_threshold * 0.7:
            return "SUSPICIOUS"
        elif n_sus > 0:
            return "MINOR_ANOMALIES"
        else:
            return "CLEAN"




def run_detection(netlist_path: str, params: dict = None,
                  save_report: bool = True) -> TrojanReport:
   
    parser = VerilogParser(netlist_path).parse()
    detector = TrojanDetector(parser, params)
    report = detector.analyze()

    if save_report:
        out = Path("results") / (Path(netlist_path).stem + "_report.json")
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(report.to_dict(), indent=2))
        print(f"  💾 Report saved → {out}")

    return report


def print_report(report: TrojanReport):
    COLORS = {
        "TROJAN_DETECTED": "\033[91m",
        "SUSPICIOUS":      "\033[93m",
        "MINOR_ANOMALIES": "\033[94m",
        "CLEAN":           "\033[92m",
        "RESET":           "\033[0m",
        "BOLD":            "\033[1m",
    }
    c = COLORS
    v_color = c.get(report.verdict, c["RESET"])

    print(f"\n{'─'*55}")
    print(f"{c['BOLD']}Module  : {report.details.get('module','?')}{c['RESET']}")
    print(f"File    : {report.file}")
    print(f"Gates   : {report.total_gates}")
    print(f"Score   : {report.anomaly_score:.4f}")
    print(f"Verdict : {v_color}{c['BOLD']}{report.verdict}{c['RESET']}")

    if report.triggering_signals:
        print(f"\n Triggering signals  : {', '.join(report.triggering_signals)}")
    if report.non_triggering_signals:
        print(f" Non-triggering sigs : {', '.join(report.non_triggering_signals)}")

    if report.suspicious_gates:
        print(f"\n Suspicious gates ({len(report.suspicious_gates)}):")
        for s in report.suspicious_gates:
            print(f"   [{s['gate']}] type={s['type']}  net={s['output_net']}")
            print(f"       flags={s['flags']}  score={s['gate_score']}")
    print(f"{'─'*55}\n")


if __name__ == "__main__":
    import sys
    import argparse

    ap = argparse.ArgumentParser(
        description="Hardware Trojan Detector for Verilog Netlists"
    )
    ap.add_argument("netlist", nargs="?", help="Path to .v netlist file")
    ap.add_argument("--fanout-threshold", type=int, default=2,
                    help="Max fanout to flag as low (default: 2)")
    ap.add_argument("--score-threshold", type=float, default=0.45,
                    help="Anomaly score threshold for TROJAN verdict (default: 0.45)")
    ap.add_argument("--batch", action="store_true",
                    help="Scan all .v files in netlists/ folder")
    ap.add_argument("--no-save", action="store_true",
                    help="Don't write JSON reports")
    args = ap.parse_args()

    params = {
        "fanout_threshold": args.fanout_threshold,
        "score_threshold":  args.score_threshold,
    }
    save = not args.no_save

    if args.batch or not args.netlist:
        files = list(Path("netlists").glob("*.v"))
        if not files:
            print("No .v files found in netlists/. Run: python trojan_detector.py netlists/your_file.v")
            sys.exit(0)
        print(f"\n🔬 Scanning {len(files)} netlist(s)…")
        for f in files:
            r = run_detection(str(f), params, save)
            print_report(r)
    else:
        r = run_detection(args.netlist, params, save)
        print_report(r)
