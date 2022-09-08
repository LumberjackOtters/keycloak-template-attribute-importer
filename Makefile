current_dir := $(notdir $(patsubst %/,%,$(dir $(mkfile_path))))

tutorial:
	@# todo: have this actually run some kind of tutorial wizard?
	@echo "Please read the 'Makefile' file to go through this tutorial"
build:
	docker run -it --rm --name my-maven-project -v "$(PWD)":/usr/src/mymaven -w /usr/src/mymaven maven:3-openjdk-11 mvn clean install
# Last but not least, `make clean` should always remove all of the stuff
# that your makefile created, so that we can remove bad stuff if anything
# gets corrupted or otherwise screwed up.
clean:
	echo "$(PWD)"

.PHONY: build clean