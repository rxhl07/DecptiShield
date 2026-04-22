import httpx

async def get_geolocation(ip_address: str):
    """
    Looks up the City and Country of an IP address.
    Returns a dictionary with location data.
    """
    # For local testing (127.0.0.1), the API won't return a city.
    # We will return a 'Demo' location so the dashboard doesn't look empty.
    if ip_address == "127.0.0.1" or ip_address.startswith("192.168"):
        return {
            "city": "Local Simulation",
            "country": "Internal Network",
            "countryCode": "LCL"
        }

    url = f"http://ip-api.com/json/{ip_address}"
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(url)
            data = response.json()
            
            if data.get("status") == "success":
                return {
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "UN")
                }
    except Exception as e:
        print(f"[Geo Error] {e}")
        
    return {"city": "Unknown", "country": "Unknown", "countryCode": "UN"}

# Quick test
if __name__ == "__main__":
    import asyncio
    # Testing with a Google DNS IP
    test_ip = "8.8.8.8"
    loc = asyncio.run(get_geolocation(test_ip))
    print(f"IP: {test_ip} | Location: {loc['city']}, {loc['country']}")