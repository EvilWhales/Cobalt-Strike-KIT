
int check_password(char* password) {
	char* actual = "oh no i haz been hax by a side channel attack!";

	while (1) {
		if (*password == '\0' || *actual == '\0') {
			return *password == *actual;
		}

		if (*password != *actual) {
			return 0;
		}

		password++;
		actual++;
	}

	return 0;
}