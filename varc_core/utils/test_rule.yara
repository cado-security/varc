rule yara_test {

	strings:
		$ = "abc123xyz987" wide ascii

	condition:
		all of them
}