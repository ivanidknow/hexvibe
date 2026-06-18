# Vulnerable: FAS-130
@app.route("/api/pack/<pack_id>", methods=["POST", "PUT"])
@cache.cached(timeout=None)  # cache until restart or manual invalidation
@login_exempt
def get_pack_multiple_modify_verb(pack_id: str) -> ApiResponse:
    pack = registry_controller.get_pack(pack_id)
    if pack is not None:
        return jsonify(pack)
    else:
        raise NotFound
