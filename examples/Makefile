all: demo_game demo_game_x86

demo_game: demo_game.c
	clang -O1 -arch arm64 -o $@ $<

# x86_64 build runs under Rosetta 2, like Wine/CrossOver games do.
demo_game_x86: demo_game.c
	clang -O1 -arch x86_64 -o $@ $<

clean:
	rm -f demo_game demo_game_x86
