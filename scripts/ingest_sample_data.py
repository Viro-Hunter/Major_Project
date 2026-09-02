#!/usr/bin/env python3
"""Ingest sample CERT data into graph store."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ingestion.log_parser import parse_cert_log
from graph.graph_store import store
from graph.updater import incremental_insert

def main():
    path = sys.argv[1] if len(sys.argv)>1 else "evaluation/datasets/cert_r4.2_sample.csv"
    # also accept --dataset flag
    if "--dataset" in sys.argv:
        idx = sys.argv.index("--dataset")
        path = sys.argv[idx+1] if idx+1 < len(sys.argv) else path
        if path == "cert_r4.2":
            path = "evaluation/datasets/cert_r4.2_sample.csv"
    print(f"Parsing {path} ...")
    events = parse_cert_log(path)
    print(f"Parsed {len(events)} events")
    incremental_insert(store, events)
    print(f"Graph: {store.num_nodes()} nodes, {store.num_edges()} edges")
    print("Sample nodes:", list(store.g.nodes)[:5])

if __name__ == "__main__":
    main()
