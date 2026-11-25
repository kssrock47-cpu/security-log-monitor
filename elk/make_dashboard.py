"""Writes elk/kibana-dashboard.ndjson: the Kibana data views, charts and dashboard for the monitor's data.

    python elk/make_dashboard.py

Import it in Kibana (Stack Management > Saved objects > Import), or let elk/start-windows.ps1 do it.
The charts are Kibana's aggregation-based visualizations, built on the ECS fields that seclog/elk.py sends.
"""
import json
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kibana-dashboard.ndjson")
EV, AL = "seclog-events", "seclog-alerts"
REF = "kibanaSavedObjectMeta.searchSourceJSON.index"
SEV_COLORS = {"critical": "#BD271E", "high": "#E7664C", "medium": "#D6BF57", "low": "#54B399"}


def search_source(query=""):
    return json.dumps({"query": {"query": query, "language": "kuery"}, "filter": [], "indexRefName": REF})


def vis(vid, title, view, vtype, params, aggs, query="", ui=None, desc=""):
    return {"type": "visualization", "id": vid, "attributes": {
        "title": title, "description": desc, "version": 1,
        "visState": json.dumps({"title": title, "type": vtype, "params": params, "aggs": aggs}),
        "uiStateJSON": json.dumps(ui or {}),
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)}},
        "references": [{"name": REF, "type": "index-pattern", "id": view}]}


def count():
    return {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"}


def terms(aid, field, schema, size=10, label=None):
    p = {"field": field, "orderBy": "1", "order": "desc", "size": size, "otherBucket": False, "missingBucket": False}
    if label:
        p["customLabel"] = label
    return {"id": aid, "enabled": True, "type": "terms", "params": p, "schema": schema}


def over_time(aid="2"):
    return {"id": aid, "enabled": True, "type": "date_histogram", "schema": "segment",
            "params": {"field": "@timestamp", "useNormalizedEsInterval": True, "interval": "auto",
                       "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}}


def bars(title_y, horizontal=False):
    cat_pos, val_pos = ("left", "bottom") if horizontal else ("bottom", "left")
    cat_labels = {"show": True, "rotate": 0, "filter": False, "truncate": 200} if horizontal else \
        {"show": True, "filter": True, "truncate": 100}
    return {"type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": cat_pos, "show": True, "style": {},
                              "scale": {"type": "linear"}, "labels": cat_labels,
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": val_pos, "show": True,
                           "style": {}, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": title_y}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": title_y, "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "lineWidth": 2, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False,
            "labels": {"show": False}, "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full",
                                                          "color": "#E7664C"},
            "detailedTooltip": True, "palette": {"type": "palette", "name": "default"}, "isVis": True}


def pie():
    return {"type": "pie", "addTooltip": True, "addLegend": True, "legendDisplay": "show", "legendSize": "large", "legendPosition": "right", "isDonut": True,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
            "palette": {"type": "palette", "name": "default"}, "distinctColors": True}


def table(per_page=10):
    return {"perPage": per_page, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False,
            "totalFunc": "sum", "percentageCol": "", "autoFitRowToContent": False}


def metric(label):
    return {"addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                       "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                       "labels": {"show": True}, "invertColors": False,
                       "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 36}}}


def metric_aggs(label):
    return [{"id": "1", "enabled": True, "type": "count", "params": {"customLabel": label}, "schema": "metric"}]


def _style(color, dynamic_size=False):
    size = ({"type": "DYNAMIC", "options": {"minSize": 6, "maxSize": 30, "field": {"name": "doc_count", "origin": "source"},
                                            "fieldMetaOptions": {"isEnabled": True, "sigma": 3}}}
            if dynamic_size else {"type": "STATIC", "options": {"size": 7}})
    return {"type": "VECTOR", "isTimeAware": True, "properties": {
        "icon": {"type": "STATIC", "options": {"value": "marker"}},
        "fillColor": {"type": "STATIC", "options": {"color": color}},
        "lineColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
        "lineWidth": {"type": "STATIC", "options": {"size": 1}},
        "iconSize": size, "iconOrientation": {"type": "STATIC", "options": {"orientation": 0}},
        "labelText": {"type": "STATIC", "options": {"value": ""}},
        "labelColor": {"type": "STATIC", "options": {"color": "#000000"}},
        "labelSize": {"type": "STATIC", "options": {"size": 14}},
        "labelBorderColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
        "symbolizeAs": {"options": {"value": "circle"}}, "labelBorderSize": {"options": {"size": "SMALL"}},
        "labelZoomRange": {"options": {"useLayerZoomRange": True, "minZoom": 0, "maxZoom": 24}},
        "labelPosition": {"options": {"position": "CENTER"}}}}


def attack_map():
    """Kibana Maps: failed logins as sized clusters, threats as points. Needs the locations Logstash adds."""
    layers = [
        {"id": "basemap", "type": "EMS_VECTOR_TILE", "label": None, "minZoom": 0, "maxZoom": 24, "alpha": 1,
         "visible": True, "style": {"type": "EMS_VECTOR_TILE"},
         "sourceDescriptor": {"type": "EMS_TMS", "isAutoSelect": True, "lightModeDefault": "road_map_desaturated"}},
        {"id": "fails", "type": "GEOJSON_VECTOR", "label": "Failed logins", "minZoom": 0, "maxZoom": 24, "alpha": 0.7,
         "visible": True, "joins": [], "style": _style("#D6BF57", dynamic_size=True),
         "query": {"query": "event.outcome:failure", "language": "kuery"},
         "sourceDescriptor": {"id": "fails-src", "type": "ES_GEO_GRID", "geoField": "source.geo.location",
                              "requestType": "point", "resolution": "COARSE", "metrics": [{"type": "count"}],
                              "applyGlobalQuery": True, "applyGlobalTime": True,
                              "indexPatternRefName": "layer_1_source_index_pattern"}},
        {"id": "threats", "type": "GEOJSON_VECTOR", "label": "Threats", "minZoom": 0, "maxZoom": 24, "alpha": 0.9,
         "visible": True, "joins": [], "style": _style("#BD271E"),
         "sourceDescriptor": {"id": "threats-src", "type": "ES_SEARCH", "geoField": "source.geo.location",
                              "scalingType": "LIMIT", "filterByMapBounds": True, "sortField": "", "sortOrder": "desc",
                              "tooltipProperties": ["rule.name", "labels.severity", "source.ip",
                                                    "source.geo.city_name", "source.geo.country_name"],
                              "topHitsSplitField": "", "topHitsSize": 1, "applyGlobalQuery": True,
                              "applyGlobalTime": True, "indexPatternRefName": "layer_2_source_index_pattern"}},
    ]
    state = {"zoom": 1.3, "center": {"lon": 40, "lat": 25}, "timeFilters": {"from": "now-24h", "to": "now"},
             "refreshConfig": {"isPaused": False, "interval": 10000}, "query": {"query": "", "language": "kuery"},
             "filters": [], "settings": {"autoFitToDataBounds": False, "initialLocation": "LAST_SAVED_LOCATION",
                                         "showScaleControl": False, "showSpatialFilters": True}}
    return {"type": "map", "id": "seclog-map", "attributes": {
        "title": "Where attacks come from", "description": "Needs Logstash for the locations (see ELK.md)",
        "mapStateJSON": json.dumps(state), "layerListJSON": json.dumps(layers),
        "uiStateJSON": json.dumps({"isLayerTOCOpen": True, "openTOCDetails": []})},
        "references": [{"name": "layer_1_source_index_pattern", "type": "index-pattern", "id": EV},
                       {"name": "layer_2_source_index_pattern", "type": "index-pattern", "id": AL}]}


def build():
    objs = [
        {"type": "index-pattern", "id": EV, "attributes": {"title": EV + "*", "name": "Security Log Monitor: log events",
                                                           "timeFieldName": "@timestamp"}, "references": []},
        {"type": "index-pattern", "id": AL, "attributes": {"title": AL + "*", "name": "Security Log Monitor: alerts",
                                                           "timeFieldName": "@timestamp"}, "references": []},
    ]
    sev_ui = {"vis": {"colors": SEV_COLORS}}
    v = [
        vis("seclog-intro", "About this dashboard", AL, "markdown",
            {"markdown": "**Security Log Monitor** sends every log line it reads and every threat it raises here. "
                         "Fields follow the Elastic Common Schema, so the same data also works in Elastic Security.\n\n"
                         "Showing the last 24 hours. Checked an older log file? Widen the time range at the top right.",
             "fontSize": 12, "openLinksInNewTab": False}, []),
        vis("seclog-n-alerts", "Threats raised", AL, "metric", metric("Threats raised"), metric_aggs("Threats raised")),
        vis("seclog-n-events", "Log lines read", EV, "metric", metric("Log lines read"), metric_aggs("Log lines read")),
        vis("seclog-n-fails", "Failed logins", EV, "metric", metric("Failed logins"), metric_aggs("Failed logins"),
            query="event.outcome:failure"),
        vis("seclog-alerts-time", "Threats over time, by severity", AL, "histogram", bars("Threats"),
            [count(), over_time(), terms("3", "labels.severity", "group", 4, "Severity")], ui=sev_ui),
        vis("seclog-events-time", "Log lines over time, by outcome", EV, "histogram", bars("Log lines"),
            [count(), over_time(), terms("3", "event.outcome", "group", 3, "Outcome")],
            ui={"vis": {"colors": {"failure": "#E7664C", "success": "#54B399", "unknown": "#D3DAE6"}}}),
        vis("seclog-tactics", "Threats by MITRE ATT&CK tactic", AL, "pie", pie(),
            [count(), terms("2", "threat.tactic.name", "segment", 7, "Tactic")]),
        vis("seclog-ai-vs-rules", "Who caught it: the AI or a known pattern", AL, "pie", pie(),
            [count(), terms("2", "rule.category", "segment", 2, "Caught by")]),
        vis("seclog-attackers", "Most active attackers", AL, "table", table(),
            [count(), terms("2", "source.ip", "bucket", 15, "Address"),
             terms("3", "source.geo.country_name", "bucket", 1, "Country")], query="source.ip:*"),
        vis("seclog-techniques", "Attack techniques seen", AL, "table", table(),
            [count(), terms("2", "threat.technique.id", "bucket", 15, "MITRE technique"),
             terms("3", "rule.name", "bucket", 1, "Threat")]),
        vis("seclog-users", "Accounts targeted by failed logins", EV, "table", table(),
            [count(), terms("2", "user.name", "bucket", 15, "Account")], query="event.outcome:failure"),
        vis("seclog-countries", "Failed logins by country", EV, "horizontal_bar", bars("Failed logins", horizontal=True),
            [count(), terms("2", "source.geo.country_name", "segment", 10, "Country")], query="event.outcome:failure"),
    ]
    search = {"type": "search", "id": "seclog-latest-alerts", "attributes": {
        "title": "Latest threats", "description": "",
        "columns": ["rule.name", "labels.severity", "source.ip", "user.name", "threat.technique.id",
                    "labels.attack_step", "labels.status", "labels.count"],
        "sort": [["@timestamp", "desc"]],
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()}},
        "references": [{"name": REF, "type": "index-pattern", "id": AL}]}
    layout = [  # (object id, type, x, y, w, h)
        ("seclog-intro", "visualization", 0, 0, 18, 8), ("seclog-n-alerts", "visualization", 18, 0, 10, 8),
        ("seclog-n-events", "visualization", 28, 0, 10, 8), ("seclog-n-fails", "visualization", 38, 0, 10, 8),
        ("seclog-alerts-time", "visualization", 0, 8, 24, 13), ("seclog-events-time", "visualization", 24, 8, 24, 13),
        ("seclog-map", "map", 0, 21, 48, 20),
        ("seclog-tactics", "visualization", 0, 41, 16, 14), ("seclog-ai-vs-rules", "visualization", 16, 41, 14, 14),
        ("seclog-countries", "visualization", 30, 41, 18, 14),
        ("seclog-attackers", "visualization", 0, 55, 16, 15), ("seclog-techniques", "visualization", 16, 55, 18, 15),
        ("seclog-users", "visualization", 34, 55, 14, 15),
        ("seclog-latest-alerts", "search", 0, 70, 48, 16),
    ]
    panels, refs = [], []
    for i, (oid, otype, x, y, w, h) in enumerate(layout, 1):
        panels.append({"version": "8.19.26", "type": otype, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                       "panelIndex": str(i), "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{i}"})
        refs.append({"name": f"panel_{i}", "type": otype, "id": oid})
    dash = {"type": "dashboard", "id": "seclog-overview", "attributes": {
        "title": "Security Log Monitor: threat overview",
        "description": "Log events and threats from the AI-Based Security Log Analysis and Threat Monitoring System",
        "panelsJSON": json.dumps(panels), "version": 1,
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True, "syncTooltips": False,
                                   "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 10000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
        "references": refs}
    return objs + v + [search, attack_map(), dash]


if __name__ == "__main__":
    with open(OUT, "w", newline="\n") as f:
        for o in build():
            f.write(json.dumps(o) + "\n")
    print(f"Wrote {OUT}")
