#!/usr/bin/env python3
# doom_demake.py
# A DOOM-inspired raycasting game for the Raspyjack.
# Stage 4: The AI - Enemies now detect and chase the player.

import sys
import os
import time
import signal
import math
import RPi.GPIO as GPIO
from PIL import Image, ImageDraw, ImageFont

# --- Add Raspyjack root to Python path ---
RASPYJACK_ROOT = '/root/Raspyjack'
if os.path.isdir(RASPYJACK_ROOT) and RASPYJACK_ROOT not in sys.path:
    sys.path.insert(0, RASPYJACK_ROOT)

# --- Hardware Imports ---
import LCD_Config
import LCD_1in44

# --- Game Configuration ---
SCREEN_WIDTH = 128
SCREEN_HEIGHT = 128
FOV = math.pi / 3.0
DEPTH = 16.0
MOVE_SPEED = 2.0
TURN_SPEED = 1.5
ENEMY_SPEED = 1.0
ENEMY_SIGHT_RADIUS = 5.0

# --- Map ---
MAP_WIDTH = 16
MAP_HEIGHT = 16
game_map = (
    "################"
    "#..............#"
    "#..##........#.#"
    "#..##........#.#"
    "#..##..##....#.#"
    "#......##....#.#"
    "#............#.#"
    "#####........#.#"
    "#...#........#.#"
    "#...#..#.......#"
    "#...#..#.......#"
    "#...#..#.......#"
    "#...#..#######.#"
    "#..............#"
    "#..............#"
    "################"
)

# --- Sprites ---
sprite_textures = {}
sprites = [
    {"x": 10.5, "y": 4.5, "texture": "cacodemon", "state": "idle"},
    {"x": 7.5, "y": 10.5, "texture": "cacodemon", "state": "idle"},
    {"x": 3.5, "y": 13.5, "texture": "cacodemon", "state": "idle"},
]

# --- Player & Game State ---
player_x = 8.0
player_y = 8.0
player_a = 0.0
shoot_cooldown = 0.0
muzzle_flash_timer = 0.0
game_won = False

# --- Hardware and State ---
PINS = {
    "UP": 6, "DOWN": 19, "LEFT": 5, "RIGHT": 26,
    "KEY_PRESS": 13, "KEY1": 21, "KEY2": 20, "KEY3": 16
}
RUNNING = True
LCD = None

# --- Cleanup Function ---
def cleanup(*_):
    global RUNNING
    if not RUNNING: return
    RUNNING = False
    print("DOOM Demake: Cleaning up GPIO...")
    if LCD: LCD.LCD_Clear()
    GPIO.cleanup()
    print("DOOM Demake: Exiting.")
    sys.exit(0)

def create_cacodemon_sprite(size=64):
    sprite_img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(sprite_img)
    d.ellipse([(4, 4), (size-4, size-4)], fill="red", outline="darkred", width=2)
    d.ellipse([(size*0.4, size*0.25), (size*0.6, size*0.45)], fill="white")
    d.ellipse([(size*0.45, size*0.3), (size*0.55, size*0.4)], fill="black")
    d.polygon([(size*0.5, 0), (size*0.4, 10), (size*0.6, 10)], fill="yellow")
    return sprite_img

# --- Main Execution Block ---
if __name__ == "__main__":
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        GPIO.setmode(GPIO.BCM)
        for pin in PINS.values(): GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        LCD = LCD_1in44.LCD()
        LCD.LCD_Init(LCD_1in44.SCAN_DIR_DFT)
        LCD.LCD_Clear()

        sprite_textures["cacodemon"] = create_cacodemon_sprite()
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 20)

        image = Image.new("RGB", (SCREEN_WIDTH, SCREEN_HEIGHT), "BLACK")
        draw = ImageDraw.Draw(image)
        
        depth_buffer = [0] * SCREEN_WIDTH
        last_frame_time = time.time()

        while RUNNING:
            current_time = time.time()
            elapsed_time = current_time - last_frame_time
            last_frame_time = current_time
            shoot_cooldown -= elapsed_time
            muzzle_flash_timer -= elapsed_time

            # --- Input ---
            if not game_won:
                if GPIO.input(PINS["LEFT"]) == 0: player_a -= TURN_SPEED * elapsed_time
                if GPIO.input(PINS["RIGHT"]) == 0: player_a += TURN_SPEED * elapsed_time
                if GPIO.input(PINS["UP"]) == 0:
                    new_x = player_x + math.sin(player_a) * MOVE_SPEED * elapsed_time
                    new_y = player_y + math.cos(player_a) * MOVE_SPEED * elapsed_time
                    if game_map[int(new_y) * MAP_WIDTH + int(new_x)] != '#': player_x, player_y = new_x, new_y
                if GPIO.input(PINS["DOWN"]) == 0:
                    new_x = player_x - math.sin(player_a) * MOVE_SPEED * elapsed_time
                    new_y = player_y - math.cos(player_a) * MOVE_SPEED * elapsed_time
                    if game_map[int(new_y) * MAP_WIDTH + int(new_x)] != '#': player_x, player_y = new_x, new_y
                
                if GPIO.input(PINS["KEY1"]) == 0 and shoot_cooldown <= 0:
                    shoot_cooldown = 0.5
                    muzzle_flash_timer = 0.1
                    for sprite in sorted(sprites, key=lambda s: s.get('dist', 999)):
                        if sprite['state'] != 'dead':
                            dx, dy = sprite['x'] - player_x, sprite['y'] - player_y
                            dist = (dx**2 + dy**2)**0.5
                            norm_dx, norm_dy = dx / dist, dy / dist
                            dot_product = (norm_dx * math.sin(player_a) + norm_dy * math.cos(player_a))
                            if dot_product > 0.90: # Cone of fire
                                sprite['state'] = 'dead'
                                break

            if GPIO.input(PINS["KEY3"]) == 0: break

            # --- AI Update ---
            if not game_won:
                for sprite in sprites:
                    if sprite['state'] == 'idle':
                        dist_to_player = ((player_x - sprite['x'])**2 + (player_y - sprite['y'])**2)**0.5
                        if dist_to_player < ENEMY_SIGHT_RADIUS:
                            sprite['state'] = 'chasing'
                    elif sprite['state'] == 'chasing':
                        vec_x, vec_y = player_x - sprite['x'], player_y - sprite['y']
                        dist = (vec_x**2 + vec_y**2)**0.5
                        if dist > 0:
                            vec_x, vec_y = (vec_x / dist) * ENEMY_SPEED * elapsed_time, (vec_y / dist) * ENEMY_SPEED * elapsed_time
                            new_x, new_y = sprite['x'] + vec_x, sprite['y'] + vec_y
                            if game_map[int(new_y) * MAP_WIDTH + int(new_x)] != '#':
                                sprite['x'], sprite['y'] = new_x, new_y

            # --- Rendering ---
            # Walls
            for x in range(SCREEN_WIDTH):
                ray_angle = (player_a - FOV / 2.0) + (x / float(SCREEN_WIDTH)) * FOV
                eye_x, eye_y = math.sin(ray_angle), math.cos(ray_angle)
                distance_to_wall = 0.0
                hit_wall = False
                while not hit_wall and distance_to_wall < DEPTH:
                    distance_to_wall += 0.1
                    test_x, test_y = int(player_x + eye_x * distance_to_wall), int(player_y + eye_y * distance_to_wall)
                    if not (0 <= test_x < MAP_WIDTH and 0 <= test_y < MAP_HEIGHT):
                        hit_wall, distance_to_wall = True, DEPTH
                    elif game_map[test_y * MAP_WIDTH + test_x] == '#':
                        hit_wall = True
                
                depth_buffer[x] = distance_to_wall
                ceiling = int((SCREEN_HEIGHT / 2.0) - SCREEN_HEIGHT / distance_to_wall) if distance_to_wall > 0 else SCREEN_HEIGHT
                floor = SCREEN_HEIGHT - ceiling
                shade = max(0.1, 1.0 - (distance_to_wall / DEPTH))
                wall_color = (int(100 * shade), int(100 * shade), int(255 * shade))
                draw.line([(x, 0), (x, ceiling)], fill=(0,0,0))
                draw.line([(x, ceiling), (x, floor)], fill=wall_color)
                draw.line([(x, floor), (x, SCREEN_HEIGHT)], fill=(int(50*shade), int(150*shade), int(50*shade)))

            # Sprites
            live_sprites = [s for s in sprites if s['state'] != 'dead']
            for sprite in live_sprites:
                sprite['dist'] = ((player_x - sprite['x'])**2 + (player_y - sprite['y'])**2)**0.5
            live_sprites.sort(key=lambda s: s['dist'], reverse=True)

            for sprite in live_sprites:
                rel_x, rel_y = sprite['x'] - player_x, sprite['y'] - player_y
                transform_x = rel_y * math.cos(player_a) - rel_x * math.sin(player_a)
                transform_y = rel_x * math.cos(player_a) + rel_y * math.sin(player_a)

                if transform_y > 0.5:
                    sprite_screen_x = int((SCREEN_WIDTH / 2) * (1 + (transform_x / transform_y)))
                    sprite_height = abs(int(SCREEN_HEIGHT / transform_y))
                    start_y, end_y = int((SCREEN_HEIGHT - sprite_height) / 2), int((SCREEN_HEIGHT + sprite_height) / 2)
                    start_x, end_x = int(sprite_screen_x - sprite_height / 2), int(sprite_screen_x + sprite_height / 2)
                    texture = sprite_textures[sprite['texture']]
                    
                    for stripe in range(start_x, end_x):
                        if 0 <= stripe < SCREEN_WIDTH and transform_y < depth_buffer[stripe]:
                            tex_x = int(255 * (stripe - start_x) / sprite_height) / 255
                            tex_column = texture.crop((int(tex_x * texture.width), 0, int(tex_x * texture.width) + 1, texture.height))
                            scaled_column = tex_column.resize((1, sprite_height), Image.Resampling.NEAREST)
                            image.paste(scaled_column, (stripe, start_y), scaled_column)
            
            # --- UI / HUD ---
            cx, cy = SCREEN_WIDTH // 2, SCREEN_HEIGHT // 2
            draw.line([(cx - 5, cy), (cx + 5, cy)], fill="white")
            draw.line([(cx, cy - 5), (cx, cy + 5)], fill="white")

            if muzzle_flash_timer > 0:
                d = ImageDraw.Draw(image)
                d.polygon([(cx-10, SCREEN_HEIGHT-10), (cx, SCREEN_HEIGHT-30), (cx+10, SCREEN_HEIGHT-10)], fill="yellow")

            if not game_won and all(s['state'] == 'dead' for s in sprites):
                game_won = True
            
            if game_won:
                bbox = draw.textbbox((0, 0), "VICTORY!", font=font)
                text_w, text_h = bbox[2] - bbox[0], bbox[3] - bbox[1]
                draw.text(((SCREEN_WIDTH - text_w) / 2, (SCREEN_HEIGHT - text_h) / 2), "VICTORY!", font=font, fill="yellow")

            LCD.LCD_ShowImage(image, 0, 0)

    except Exception as e:
        with open("/tmp/doom_demake.log", "a") as f:
            f.write(f"ERROR: {e}\n")
            import traceback
            traceback.print_exc(file=f)
    finally:
        cleanup()
