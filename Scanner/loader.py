def load_api_endpoints(
        filename="observed_endpoints.txt",
        base_url="http://127.0.0.1:8080"
):

    apis = []

    with open(filename, "r") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            method, path = line.split(" ", 1)

            path = path.split("?")[0]

            if (
                path.startswith("/api/")
                or path.startswith("/rest/")
                or path.startswith("/b2b/")
            ):

                apis.append(
                    base_url.rstrip("/") + path
                )

    return sorted(set(apis))
