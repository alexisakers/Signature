test:
	swift build
	cp -r TestFixtures ~/Signature-TestFixtures
	swift test

clean:
	rm -rf ~/Signature-TestFixtures
