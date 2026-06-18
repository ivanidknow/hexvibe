# Vulnerable: FAS-134
@cross_origin(supports_credentials=True, origins="*")
def get_special_data():
    # This route uses the CORS decorator for route-specific CORS settings
    return jsonify({"message": "CORS is enabled with credentials (route-specific config)!"})
@app.route('/safe-route', methods=['GET'])
