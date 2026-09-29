"""FastAPI Backend Server for InfraGraph."""
import os
import secrets
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security.api_key import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from infragraph.models.graph import InfraGraph
from infragraph.scanner import InfraScanner
from infragraph.analyzer.diff import GraphDiffEngine
from infragraph.web.sample_data import generate_sample_graph

app = FastAPI(title="InfraGraph Attack Surface Intelligence API")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# In-memory graph cache
CURRENT_GRAPH: InfraGraph = generate_sample_graph()
SAVED_SNAPSHOTS: Dict[str, InfraGraph] = {"demo_snapshot": CURRENT_GRAPH}

# ---------------------------------------------------------------------------
# Optional API Key Auth (set INFRAGRAPH_API_KEY env var to enable)
# ---------------------------------------------------------------------------

_API_KEY = os.environ.get("INFRAGRAPH_API_KEY")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_scan_auth(api_key: Optional[str] = Depends(_api_key_header)):
    """Validate API key for mutating endpoints if INFRAGRAPH_API_KEY is set."""
    if _API_KEY and not secrets.compare_digest(api_key or "", _API_KEY):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-API-Key header. Set INFRAGRAPH_API_KEY env var to enable auth."
        )


class ScanRequest(BaseModel):
    domain: str
    extra_subdomains: Optional[List[str]] = None
    enable_bruteforce: bool = True
    concurrency: int = 50


class DiffRequest(BaseModel):
    old_graph_data: Dict[str, Any]
    new_graph_data: Dict[str, Any]


@app.get("/", response_class=HTMLResponse)
async def get_index():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>InfraGraph UI not found</h1>")


@app.get("/api/graph")
async def get_current_graph():
    """Get the current graph in Cytoscape format."""
    global CURRENT_GRAPH
    return CURRENT_GRAPH.to_cytoscape()


@app.get("/api/stats")
async def get_stats():
    """Get current graph statistics."""
    global CURRENT_GRAPH
    return CURRENT_GRAPH.get_stats().model_dump()


@app.get("/api/sample")
async def load_sample_graph():
    """Reset to sample attack surface graph."""
    global CURRENT_GRAPH
    CURRENT_GRAPH = generate_sample_graph()
    return CURRENT_GRAPH.to_cytoscape()


@app.get("/api/snapshots")
async def list_snapshots():
    """List all saved graph snapshots."""
    return {
        name: {
            "name": graph.name,
            "created_at": graph.created_at,
            "stats": graph.get_stats().model_dump()
        }
        for name, graph in SAVED_SNAPSHOTS.items()
    }


@app.get("/api/snapshots/{snapshot_key}")
async def get_snapshot(snapshot_key: str):
    """Load a saved snapshot into Cytoscape format."""
    graph = SAVED_SNAPSHOTS.get(snapshot_key)
    if not graph:
        raise HTTPException(status_code=404, detail=f"Snapshot '{snapshot_key}' not found.")
    return graph.to_cytoscape()


@app.post("/api/scan", dependencies=[Depends(require_scan_auth)])
async def start_scan(req: ScanRequest):
    """Run an attack surface recon and dangling takeover scan."""
    global CURRENT_GRAPH
    domain = req.domain.strip()
    if not domain:
        raise HTTPException(status_code=400, detail="Target domain is required")

    scanner = InfraScanner(
        concurrency=req.concurrency,
        enable_active_bruteforce=req.enable_bruteforce
    )
    graph = await scanner.scan_domain(domain, extra_subdomains=req.extra_subdomains)
    CURRENT_GRAPH = graph
    SAVED_SNAPSHOTS[domain] = graph
    return graph.to_cytoscape()


@app.post("/api/diff")
async def compute_diff(req: DiffRequest):
    """Compute differential between two graph snapshots."""
    try:
        old_g = InfraGraph.from_dict(req.old_graph_data)
        new_g = InfraGraph.from_dict(req.new_graph_data)
        delta = GraphDiffEngine.compare(old_g, new_g)
        return delta.model_dump()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to diff graphs: {str(e)}")


@app.get("/api/export/dot")
async def export_dot():
    """Export current graph to Graphviz DOT format."""
    global CURRENT_GRAPH
    return {"dot": CURRENT_GRAPH.to_dot()}

