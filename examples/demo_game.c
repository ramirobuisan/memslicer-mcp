// A tiny stand-in "game" for testing memslicer end to end.
//
// Values live on the heap behind a global pointer, like a real game, so a
// pointer scan has something to find:  g_world -> World -> Player.
// HP drops and gold rises on their own every couple of seconds, so a scan can be
// narrowed without touching the keyboard. Press Enter to heal to full.
//
//   make -C examples            # builds demo_game (arm64) and demo_game_x86 (runs under Rosetta)
//   ./examples/demo_game

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

typedef struct {
    char name[16];
    int32_t hp;
    int32_t max_hp;
    float speed;
    int64_t gold;
    double x, y, z;
} Player;

typedef struct {
    int32_t frame;
    int32_t level;
    Player *player;
} World;

World *g_world;

int main(void) {
    srand((unsigned)getpid());
    // Pad the heap so the interesting allocations aren't at a predictable spot.
    for (int i = 0; i < 1000 + rand() % 1000; i++) (void)malloc(64 + rand() % 512);

    g_world = calloc(1, sizeof(World));
    g_world->level = 1;
    g_world->player = calloc(1, sizeof(Player));
    Player *p = g_world->player;
    strcpy(p->name, "Hero");
    p->max_hp = p->hp = 100;
    p->speed = 1.5f;
    p->gold = 250;

    printf("demo_game pid %d (Enter = heal)\n", getpid());
    for (;;) {
        g_world->frame++;
        if (g_world->frame % 2 == 0 && p->hp > 0) p->hp -= 1 + rand() % 9;
        if (g_world->frame % 3 == 0) p->gold += 10 + rand() % 90;
        p->x += p->speed;
        if (p->hp < 0) p->hp = 0;
        printf("frame %4d  HP %3d/%d  gold %lld  speed %.2f  x %.1f\n", g_world->frame, p->hp, p->max_hp,
               (long long)p->gold, p->speed, p->x);
        fflush(stdout);

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        struct timeval tv = {1, 0};
        if (select(1, &fds, NULL, NULL, &tv) > 0) {
            char line[64];
            if (!fgets(line, sizeof line, stdin)) {
                sleep(1);  // stdin closed (running in the background): keep going
                continue;
            }
            p->hp = p->max_hp;
        }
    }
}
