#!/usr/bin/env python3
import sys, re, json
from collections import defaultdict, Counter
from pathlib import Path

RE_INTERFACE = re.compile(r'^interface\s+(\S+)', re.I)
RE_NAMEIF = re.compile(r'^\s*nameif\s+(\S+)', re.I)
RE_SECURITY_LEVEL = re.compile(r'^\s*security-level\s+(\d+)', re.I)
RE_IP_ADDR = re.compile(r'^\s*ip\s+address\s+(\S+)\s+(\S+)(?:\s+standby\s+\S+\s+\S+)?', re.I)
RE_VLAN = re.compile(r'^\s*vlan\s+(\d+)', re.I)
RE_SUBINT = re.compile(r'^\w+(?:Ethernet|Management)\d+/\d+\.(\d+)$', re.I)

RE_ACCESS_LIST = re.compile(r'^\s*access-list\s+(\S+)\s+(extended|standard)\s+(permit|deny)\s+(.+)', re.I)
RE_ACCESS_GROUP = re.compile(r'^\s*access-group\s+(\S+)\s+in\s+interface\s+(\S+)', re.I)

RE_USES_OBJECT = re.compile(r'\bobject(?:-group)?\b', re.I)

RISKY_PORTS = {
    ("tcp","23"),("tcp","21"),("tcp","3389"),("tcp","445"),("tcp","139"),
    ("tcp","1433"),("tcp","3306"),("tcp","5900"),("tcp","25"),("tcp","110"),
    ("tcp","143"),("tcp","2049"),("tcp","2375"),("tcp","5985"),("tcp","5986"),
    ("udp","161"),("udp","162"),("udp","69"),("udp","2049"),
}
RISKY_PROTOCOLS = {"ip"}

class Interface:
    def __init__(self, ifname):
        self.ifname=ifname; self.nameif=None; self.security_level=None
        self.ip=None; self.mask=None; self.vlan=None
    def to_dict(self):
        return {"ifname":self.ifname,"nameif":self.nameif,"security_level":self.security_level,
                "ip":self.ip,"mask":self.mask,"vlan":self.vlan}

class ACE:
    def __init__(self, acl, acl_type, action, raw, line_no):
        self.acl=acl; self.acl_type=acl_type.lower(); self.action=action.lower()
        self.raw=raw.strip(); self.line_no=line_no
        self.uses_object=bool(RE_USES_OBJECT.search(raw))
        self.protocol=None; self.src=None; self.dst=None; self.src_ports=[]; self.dst_ports=[]
        self._parse_tokens()

    def _parse_tokens(self):
        toks=self.raw.split()
        if not toks: return
        try:
            self.protocol=toks[0].lower(); pos=1
            self.src,pos=_parse_addr_entity(toks,pos); self.src_ports,pos=_parse_port_ops(toks,pos)
            self.dst,pos=_parse_addr_entity(toks,pos); self.dst_ports,pos=_parse_port_ops(toks,pos)
        except: pass

    def normalized(self):
        return json.dumps({
            "acl": self.acl.lower(),"type": self.acl_type,"action": self.action,
            "protocol": self.protocol or "","src": self.src or "","src_ports": sorted(self.src_ports),
            "dst": self.dst or "","dst_ports": sorted(self.dst_ports),"uses_object": self.uses_object
        }, sort_keys=True)

    def is_allow_all(self):
        if self.action!="permit" or not self.protocol: return False
        if (self.src in {"any","any4","any6"}) and (self.dst in {"any","any4","any6"}):
            if self.protocol=="ip": return True
            if self.protocol in {"tcp","udp","icmp"} and not self.dst_ports: return True
        return False

    def is_potentially_dangerous(self):
        if self.action!="permit": return False
        if self.protocol and self.protocol.lower() in RISKY_PROTOCOLS and \
           (self.src in {"any","any4","any6"} and self.dst in {"any","any4","any6"}):
            return True
        if (self.protocol or "").lower() in {"tcp","udp"} and self.src in {"any","any4","any6"}:
            for p in self.dst_ports:
                if (self.protocol.lower(), p) in RISKY_PORTS: return True
        return False

    def to_dict(self):
        return {"acl":self.acl,"type":self.acl_type,"action":self.action,"protocol":self.protocol,
                "src":self.src,"src_ports":self.src_ports,"dst":self.dst,"dst_ports":self.dst_ports,
                "uses_object":self.uses_object,"raw":self.raw,"line_no":self.line_no}

def _looks_like_ip(s:str)->bool:
    parts=s.split(".")
    if len(parts)!=4: return False
    try: return all(0<=int(p)<=255 for p in parts)
    except: return False

def _parse_addr_entity(tokens,pos):
    if pos>=len(tokens): return None,pos
    t=tokens[pos].lower()
    if t in {"any","any4","any6"}: return t,pos+1
    if t=="host" and pos+1<len(tokens): return f"host {tokens[pos+1]}", pos+2
    if t in {"object","object-group"} and pos+1<len(tokens): return f"{t} {tokens[pos+1]}", pos+2
    if _looks_like_ip(tokens[pos]):
        if pos+1<len(tokens) and _looks_like_ip(tokens[pos+1]):
            return f"{tokens[pos]}/{tokens[pos+1]}", pos+2
        return tokens[pos], pos+1
    return tokens[pos], pos+1

def _parse_port_ops(tokens,pos):
    ports=[]
    while pos<len(tokens):
        t=tokens[pos].lower()
        if t=="eq" and pos+1<len(tokens):
            ports.append(tokens[pos+1].lower()); pos+=2; continue
        if t=="range" and pos+2<len(tokens):
            ports.append(f"{tokens[pos+1].lower()}-{tokens[pos+2].lower()}"); pos+=3; continue
        if t in {"any","host","object","object-group"} or _looks_like_ip(tokens[pos]): break
        if t in {"tcp","udp","ip","icmp"}: break
        break
    return ports,pos

OBJ_NONE=0; OBJ_NETWORK=1; OBJ_SERVICE=2
G_NONE=0; G_NET=1; G_SVC=2; G_PROTO=3; G_ICMP=4

def parse_config(lines):
    interfaces=[]; iface_map={}; current_if=None
    acls=defaultdict(list); access_groups={}
    objects={"network":{}, "service":{}}
    obj_ctx=(OBJ_NONE,None)
    groups={"network":{}, "service":{}, "protocol":{}, "icmp-type":{}}
    grp_ctx=(G_NONE,None)

    for idx, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith(("!","#")): 
            # leaving a block on '!' helps avoid sticky contexts in odd dumps
            continue

        # interface
        m=RE_INTERFACE.match(s)
        if m:
            ifname=m.group(1); current_if=Interface(ifname)
            interfaces.append(current_if); iface_map[ifname]=current_if
            obj_ctx=(OBJ_NONE,None); grp_ctx=(G_NONE,None)
            continue

        # inside interface (non-consuming)
        if current_if:
            n=RE_NAMEIF.match(s)
            if n: current_if.nameif=n.group(1); continue
            sec=RE_SECURITY_LEVEL.match(s)
            if sec: current_if.security_level=int(sec.group(1)); continue
            ip=RE_IP_ADDR.match(s)
            if ip: current_if.ip=ip.group(1); current_if.mask=ip.group(2); continue
            v=RE_VLAN.match(s)
            if v: current_if.vlan=v.group(1); continue
            subm=RE_SUBINT.search(current_if.ifname)
            if subm and not current_if.vlan: current_if.vlan=subm.group(1)

        # object start
        low=s.lower()
        if low.startswith("object network "):
            name=s.split(None,2)[2]
            objects["network"].setdefault(name, {"type":"network","name":name,"members":[],"meta":[]})
            obj_ctx=(OBJ_NETWORK,name); grp_ctx=(G_NONE,None)
            continue
        if low.startswith("object service "):
            name=s.split(None,2)[2]
            objects["service"].setdefault(name, {"type":"service","name":name,"protocol":None,"src_ports":[],"dst_ports":[],"meta":[]})
            obj_ctx=(OBJ_SERVICE,name); grp_ctx=(G_NONE,None)
            continue

        # object contents
        if obj_ctx[0]!=OBJ_NONE:
            typ,name=obj_ctx
            if low=="exit":
                obj_ctx=(OBJ_NONE,None)
                continue
            if typ==OBJ_NETWORK:
                if low.startswith("host "):
                    objects["network"][name]["members"].append(f"host {s.split(None,1)[1]}")
                    continue
                if low.startswith("subnet "):
                    parts=s.split()
                    if len(parts)>=3:
                        objects["network"][name]["members"].append(f"{parts[1]}/{parts[2]}")
                        continue
                if low.startswith("range "):
                    parts=s.split()
                    if len(parts)>=3:
                        objects["network"][name]["members"].append(f"range {parts[1]}-{parts[2]}")
                        continue
                if low.startswith("fqdn "):
                    fq=s.split()[-1]
                    objects["network"][name]["members"].append(f"fqdn {fq}")
                    continue
                if low.startswith(("description ","nat ")):
                    objects["network"][name]["meta"].append(s)
                    continue
            elif typ==OBJ_SERVICE:
                if low.startswith("service "):
                    toks=s.split(); proto=toks[1].lower()
                    o=objects["service"][name]; o["protocol"]=proto
                    def _grab(idx_word, target):
                        if idx_word in toks:
                            i=toks.index(idx_word)
                            if i+1<len(toks) and toks[i+1]=="eq" and i+2<len(toks):
                                target.append(toks[i+2].lower())
                            elif i+1<len(toks) and toks[i+1]=="range" and i+3<len(toks):
                                target.append(f"{toks[i+2].lower()}-{toks[i+3].lower()}")
                    _grab("source", o["src_ports"]); _grab("destination", o["dst_ports"])
                    continue
                if low.startswith(("description ","timeout ","inspect ")):
                    objects["service"][name]["meta"].append(s)
                    continue
            # if not recognized inside object, just fall through (don’t eat ACL lines)

        # object-group start
        if low.startswith("object-group "):
            parts=s.split()
            kind=parts[1].lower(); name=parts[2]
            kind_map={"network":G_NET,"service":G_SVC,"protocol":G_PROTO,"icmp-type":G_ICMP}
            gk=kind_map.get(kind,G_NONE)
            store={"network":"network","service":"service","protocol":"protocol","icmp-type":"icmp-type"}.get(kind)
            if gk!=G_NONE and store:
                groups[store].setdefault(name, {"type":store,"name":name,"members":[],"groups":[]})
                grp_ctx=(gk,name); obj_ctx=(OBJ_NONE,None)
                continue

        # object-group contents
        if grp_ctx[0]!=G_NONE:
            gk,gname=grp_ctx
            if low=="exit":
                grp_ctx=(G_NONE,None)
                continue
            if gk==G_NET:
                if low.startswith("group-object "):
                    groups["network"][gname]["groups"].append(s.split(None,1)[1]); continue
                if low.startswith("network-object "):
                    groups["network"][gname]["members"].append(s.split(None,1)[1]); continue
            elif gk==G_SVC:
                if low.startswith("group-object "):
                    groups["service"][gname]["groups"].append(s.split(None,1)[1]); continue
                if low.startswith("service-object "):
                    groups["service"][gname]["members"].append(s.split(None,1)[1]); continue
                if low.startswith("port-object "):
                    groups["service"][gname]["members"].append(f"port {s.split(None,1)[1]}"); continue
            elif gk==G_PROTO:
                if low.startswith("group-object "):
                    groups["protocol"][gname]["groups"].append(s.split(None,1)[1]); continue
                if low.startswith("protocol-object "):
                    groups["protocol"][gname]["members"].append(s.split(None,1)[1]); continue
            elif gk==G_ICMP:
                if low.startswith("group-object "):
                    groups["icmp-type"][gname]["groups"].append(s.split(None,1)[1]); continue
                if low.startswith(("icmp-object ","icmp-type ")):
                    groups["icmp-type"][gname]["members"].append(s.split(None,1)[1]); continue
            # if not recognized, fall through

        # ACLs & bindings (must be reachable regardless of prior contexts)
        m=RE_ACCESS_LIST.match(s)
        if m:
            acl_name, acl_type, action, rest = m.groups()
            acls[acl_name].append(ACE(acl_name, acl_type, action, rest, idx))
            continue
        m=RE_ACCESS_GROUP.match(s)
        if m:
            acl_name, intf = m.groups()
            access_groups[acl_name]=intf
            continue

    return interfaces, acls, access_groups, objects, groups

def expand_group(groups, objects, kind, name, _seen=None):
    if name not in groups.get(kind, {}): return {"members":[],"groups":[]}
    if _seen is None: _seen=set()
    key=(kind,name)
    if key in _seen: return {"members":[f"#cycle:{name}"],"groups":[]}
    _seen.add(key)
    out_m=[]; out_g=[]; entry=groups[kind][name]
    out_m.extend(entry.get("members",[]))
    for g in entry.get("groups",[]):
        out_g.append(g)
        sub=expand_group(groups, objects, kind, g, _seen)
        out_m.extend(sub["members"]); out_g.extend(sub["groups"])
    if kind=="network":
        for m in list(out_m):
            lm=m.lower()
            if lm.startswith("object "):
                on=m.split(None,1)[1]
                if on in objects["network"]:
                    out_m.extend(objects["network"][on]["members"])
    return {"members": _dedupe(out_m), "groups": _dedupe(out_g)}

def _dedupe(seq):
    seen=set(); out=[]
    for x in seq:
        if x not in seen:
            out.append(x); seen.add(x)
    return out

def analyze(interfaces, acls, access_groups, objects, groups):
    results={"interfaces":[i.to_dict() for i in interfaces],
             "vlans": sorted({i.vlan for i in interfaces if i.vlan}),
             "acl_bindings": access_groups,
             "allow_all_rules": [], "duplicate_rules": [], "dangerous_rules": [],
             "objects": objects, "object_groups_raw": groups, "object_groups_expanded": {},
             "summary": {}, "notes": []}

    for k in ["network","service","protocol","icmp-type"]:
        results["object_groups_expanded"][k]={}
        for name in groups[k]:
            results["object_groups_expanded"][k][name]=expand_group(groups, objects, k, name)

    for _, entries in acls.items():
        seen=Counter(e.normalized() for e in entries)
        for e in entries:
            if seen[e.normalized()]>1:
                results["duplicate_rules"].append(_ace_record(e, access_groups))

    for acl_name, entries in acls.items():
        bound_if=access_groups.get(acl_name)
        for e in entries:
            if e.is_allow_all():
                results["allow_all_rules"].append(_ace_record(e, access_groups))
            if e.is_potentially_dangerous():
                risk="medium"
                if bound_if and "outside" in bound_if.lower(): risk="high"
                results["dangerous_rules"].append(_ace_record(e, access_groups, risk=risk))

    results["summary"]={
        "interfaces_total": len(interfaces),
        "vlans_total": len(results["vlans"]),
        "acls_total": len(acls),
        "aces_total": sum(len(v) for v in acls.values()),
        "allow_all_count": len(results["allow_all_rules"]),
        "duplicate_count": len(results["duplicate_rules"]),
        "dangerous_count": len(results["dangerous_rules"]),
        "objects_network": len(objects["network"]),
        "objects_service": len(objects["service"]),
        "groups_network": len(groups["network"]),
        "groups_service": len(groups["service"]),
        "groups_protocol": len(groups["protocol"]),
        "groups_icmp": len(groups["icmp-type"]),
    }
    if any(e["uses_object"] for e in results["allow_all_rules"]+results["dangerous_rules"]):
        results["notes"].append("Some ACEs reference objects/object-groups; expansion shown separately.")
    if not access_groups:
        results["notes"].append("No access-group bindings found; cannot assess inbound interface risk.")
    return results

def _ace_record(e, bindings, risk=None):
    return {**e.to_dict(), "bound_interface": bindings.get(e.acl), "risk":risk}

def print_report(results):
    print("="*72); print("ASA Running-Config Security Audit (with Objects)"); print("="*72)
    print("\nInterfaces:")
    for i in results["interfaces"]:
        line=f"- {i['ifname']}"
        if i.get("nameif"): line+=f" (nameif: {i['nameif']})"
        if i.get("security_level") is not None: line+=f", sec-level: {i['security_level']}"
        if i.get("ip"): line+=f", ip: {i['ip']} {i.get('mask','')}"
        if i.get("vlan"): line+=f", vlan: {i['vlan']}"
        print(line)
    if results["vlans"]:
        print("\nVLANs:", ", ".join(results["vlans"]))

    if results["acl_bindings"]:
        print("\nACL Bindings (in):")
        for acl,intf in results["acl_bindings"].items():
            print(f"- {acl} -> interface {intf}")

    def _print_ace_list(title, items, limit=50):
        print(f"\n{title} ({len(items)}):")
        if not items: print("  None"); return
        for rec in items[:limit]:
            where=f" [bound to: {rec.get('bound_interface')}] " if rec.get("bound_interface") else " "
            risk=f"(risk: {rec.get('risk')}) " if rec.get("risk") else ""
            print(f"- ACL {rec['acl']}{where}{risk}{rec['action']} {rec['protocol']} "
                  f"{rec.get('src')} {('src_ports='+','.join(rec['src_ports'])+' ') if rec['src_ports'] else ''}"
                  f"{rec.get('dst')} {('dst_ports='+','.join(rec['dst_ports'])) if rec['dst_ports'] else ''} "
                  f"[line {rec['line_no']}]" + (" [uses object]" if rec.get("uses_object") else ""))

    _print_ace_list("Allow-all rules", results["allow_all_rules"])
    _print_ace_list("Duplicate rules", results["duplicate_rules"])
    _print_ace_list("Potentially dangerous rules", results["dangerous_rules"])

    if results["objects"]["network"]:
        print("\nObject NETWORK (count: %d):" % len(results["objects"]["network"]))
        for name, obj in list(results["objects"]["network"].items())[:50]:
            print(f"- {name}: members={obj['members'] or ['(empty)']}")
    if results["objects"]["service"]:
        print("\nObject SERVICE (count: %d):" % len(results["objects"]["service"]))
        for name, obj in list(results["objects"]["service"].items())[:50]:
            proto=obj.get("protocol"); sp=obj.get("src_ports"); dp=obj.get("dst_ports")
            print(f"- {name}: proto={proto} src_ports={sp or ['any']} dst_ports={dp or ['any']}")

    def _print_group(kind, limit=50):
        src=results["object_groups_expanded"][kind]
        print(f"\nObject-Group {kind.upper()} (count: {len(src)}):")
        if not src: print("  None"); return
        for name, exp in list(src.items())[:limit]:
            print(f"- {name}: members={exp['members'] or ['(empty)']} nested_groups={exp['groups'] or []}")
    for k in ["network","service","protocol","icmp-type"]:
        _print_group(k)

    print("\nSummary:")
    for k,v in results["summary"].items():
        print(f"- {k.replace('_',' ').title()}: {v}")

    if results["notes"]:
        print("\nNotes:")
        for n in results["notes"]: print(f"- {n}")

def main():
    if len(sys.argv)!=2:
        print("Usage: python asa_audit.py <running-config.txt>", file=sys.stderr); sys.exit(1)
    cfg=Path(sys.argv[1])
    if not cfg.is_file():
        print(f"File not found: {cfg}", file=sys.stderr); sys.exit(2)
    with cfg.open("r", encoding="utf-8", errors="ignore") as f:
        lines=f.readlines()
    interfaces, acls, access_groups, objects, groups = parse_config(lines)
    results = analyze(interfaces, acls, access_groups, objects, groups)
    print_report(results)
    out=cfg.with_name("asa_audit_report.json")
    with out.open("w", encoding="utf-8") as f: json.dump(results, f, indent=2)
    print(f"\nJSON report written to: {out}")

if __name__=="__main__":
    main()
