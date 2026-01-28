"""Deze functie regelt alle code voor de simulatie binnen de visualisatie"""

# als eerst importeren we alle open source libraries die nodig zijn en alle waardes en functies van CrashGuardIEEE
from CrashGuardIEEE import MESSAGE, decoder, terminal
import importlib.resources
import pygame

# We definieren vooraf de grootte van de window in pixels en de frames per seconde
WINDOW_SIZE = (900, 600)
FPS = 60

"""De class 'Dropdown' maakt het mogelijk om dropdown menus in de window te gebruiken."""
class Dropdown:
    # definieer de waardes van een dropdown menu
    def __init__(self, rect, options, font, default=0):
        self.rect = pygame.Rect(rect)
        self.options = options
        self.font = font
        self.open = False
        self.selected = default

    # reageer op keuze selectie
    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            if self.open:
                for i, _ in enumerate(self.options):
                    opt_rect = pygame.Rect(self.rect.x, self.rect.y + (i + 1) * self.rect.height, self.rect.width, self.rect.height)
                    if opt_rect.collidepoint(event.pos):
                        self.selected = i
                        self.open = False
                        return True
                if not self.rect.collidepoint(event.pos):
                    self.open = False
            else:
                if self.rect.collidepoint(event.pos):
                    self.open = True
                    return True
        return False

    # graphics voor het drop down menu
    def draw(self, surf):
        pygame.draw.rect(surf, (200, 200, 200), self.rect)
        txt = self.font.render(self.options[self.selected], True, (0, 0, 0))
        surf.blit(txt, (self.rect.x + 6, self.rect.y + 6))
        pygame.draw.rect(surf, (100, 100, 100), self.rect, 2)

        if self.open:
            total_height = len(self.options) * self.rect.height
            bg_rect = pygame.Rect(self.rect.x, self.rect.y + self.rect.height, self.rect.width, total_height)
            pygame.draw.rect(surf, (230, 230, 230), bg_rect)
            
            for i, opt in enumerate(self.options):
                opt_rect = pygame.Rect(self.rect.x, self.rect.y + (i + 1) * self.rect.height, self.rect.width, self.rect.height)
                o_txt = self.font.render(opt, True, (0, 0, 0))
                surf.blit(o_txt, (opt_rect.x + 6, opt_rect.y + 6))
                pygame.draw.rect(surf, (100, 100, 100), opt_rect, 1)

"""De class 'Button' maakt het mogelijk om knoppen in de window te gebruiken."""
class Button:
    # definieer de waardes voor een button
    def __init__(self, rect, text, font):
        self.rect = pygame.Rect(rect)
        self.text = text
        self.font = font

    # graphics voor de button
    def draw(self, surf):
        pygame.draw.rect(surf, (100, 180, 100), self.rect)
        txt = self.font.render(self.text, True, (0, 0, 0))
        surf.blit(txt, (self.rect.x + 8, self.rect.y + 6))
        pygame.draw.rect(surf, (50, 100, 50), self.rect, 2)

    # regel kliks
    def clicked(self, event):
        return event.type == pygame.MOUSEBUTTONDOWN and event.button == 1 and self.rect.collidepoint(event.pos)

"""De class 'Simulation' is verantwoordelijk voor de logica tijdens de visualisatie, zoals het versturen en uitpakken van een bericht."""
class Simulation:
    # definieer waardes voor simulatie
    def __init__(self, surface, font, mode, assets):
        self.surface = surface
        self.font = font
        self.mode = mode
        self.Pijlwagen_pos = [100, 280] 
        self.car_pos = [700, 280] 
        self.car_lane = 0 
        self.target_lane = 0
        self.lane_switching = False
        self.lane_switch_timer = 0.0
        self.can_return_to_center = True  
        self.log = []
        self.log_scroll_offset = 0 
        self.speed = 120.0
        self.paused = False
        self.reaction_timer = 0.0
        self.reaction_duration = 1.5
        self.prev_speed = self.speed
        self.target_speed = None
        self.flash = 0.0
        self.packet_active = False
        self.packet_progress = 0.0
        self.packet_duration = 0.8
        self.packet_color = (255, 200, 0)
        self.warning_distance = 500 
        self.message_sent = False 
        self.last_message_mode = None
        self.packet_pos = [0, 0]
        self.car_reaction_timer = 0.0
        self.car_reaction_duration = 0.6
        self.car_flash = 0.0
        self.signal_blink = 0.0
        self.signal_duration = 0.0
        self.signal_type = None
        self.json_rapport = None # bevat het resulaat van de validatie van de decoder
        self.assets = assets # bevat de PNG afbeelding van de pijlwagen

    """de functie 'C_send_message' start het sturen van een bericht en stuurt de gekleurde beam naar de auto"""
    def C_send_message(self, mode):
        processed_result = self.C_execute_ieee(mode)
        self.json_rapport = processed_result

        self.log.append(f"[Voertuig]: V2X bericht uitpakken [{mode}]...")
        
        # bepaal bericht kleur op basis van de content type
        if mode == 'unsecure':
            self._start_reaction(intensity=0.2)
            self.packet_color = (200, 200, 200)
        elif mode == 'signed':
            self._start_reaction(intensity=0.6)
            self.packet_color = (80, 200, 240)
        elif mode == 'encrypted':
            self._start_reaction(intensity=0.8)
            self.packet_color = (200, 140, 240)
        elif mode == 'enveloped':
            self._start_reaction(intensity=1.0)
            self.packet_color = (20, 240, 40)

        # beweeg het gekleurde bericht
        self.packet_active = True
        self.packet_progress = 0.0
        self.packet_duration = 0.5 + (0.6 if mode == 'enveloped' else 0.2)
        self.packet_pos[0], self.packet_pos[1] = self.Pijlwagen_pos[0], self.Pijlwagen_pos[1]

    """de functie 'C_execute_ieee' regelt het uitpakken van het ontvangen bericht"""
    def C_execute_ieee(self, mode):
        # probeer het bericht uit te pakken op basis van het content type, anders geef een error
        if mode == 'unsecure':
            try:
                values, validation = decoder.get_decoded_unsecure(payload=MESSAGE)
                return [values, validation]
            except Exception as e:
                terminal.text(text=f"ERROR: content type incorrect?\n{e}", color="red")
        elif mode == 'signed':
            try:
                values, validation = decoder.get_decoded_signed(payload=MESSAGE)
                return [values, validation]
            except Exception as e:
                terminal.text(text=f"ERROR: content type incorrect?\n{e}", color="red")
        elif mode == 'encrypted':
            try:
                values, validation = decoder.get_decoded_encrypted(payload=MESSAGE)
                return [values, validation]
            except Exception as e:
                    terminal.text(text=f"ERROR: content type incorrect?\n{e}", color="red")
        elif mode == 'enveloped':
            try:
                values, validation = decoder.get_decoded_enveloped(payload=MESSAGE)
                return [values, validation]
            except Exception as e:
                terminal.text(text=f"ERROR: content type incorrect?\n{e}", color="red")
        return None

    """de functie 'C_send_message_instant' stuurt direct een bericht op exact dezelfde manier als C_send_message
    deze functie is outdated en wordt niet meer gebruikt!"""
    def C_send_message_instant(self, mode):
        processed_result = self.C_execute_ieee(mode)
        self.json_rapport = processed_result
        self.log.append(f"[Voertuig]: V2X bericht uitpakken [{mode}]...")
        
        # bepaal bericht kleur op basis van de content type
        if mode == 'Not secured':
            self.packet_color = (200, 200, 200)
        elif mode == 'Certified':
            self.packet_color = (80, 200, 240)
        elif mode == 'Enveloped':
            self.packet_color = (200, 140, 240)
        
        # beweeg het gekleurde bericht
        self.packet_active = True
        self.packet_progress = 0.0
        self.packet_duration = 1.0 
        self.packet_pos[0], self.packet_pos[1] = self.Pijlwagen_pos[0], self.Pijlwagen_pos[1]

    """de functie 'set_speed' stelt een nieuwe snelheid in van het voertuig"""
    def set_speed(self, new_speed: float):
        self.speed = max(-400.0, min(400.0, new_speed))

    """de functie 'increase_speed' stelt een verhoogt de snelheid van het voertuig"""
    def increase_speed(self, delta=20.0):
        self.set_speed(self.speed + delta)

    """de functie 'decrease_speed' stelt een verlaagt de snelheid van het voertuig"""
    def decrease_speed(self, delta=20.0):
        self.set_speed(self.speed - delta)

    """de functie 'toggle_pause' geeft de optie om de simulatie op pauze te zetten"""
    def toggle_pause(self):
        self.paused = not self.paused

    """de functie 'update' regelt de real time logica per frame"""
    def update(self, dt):
        # als de auto dichtbij genoeg komt, stuur een bericht
        distance_to_car = abs(self.car_pos[0] - self.Pijlwagen_pos[0])
        if distance_to_car <= self.warning_distance and not self.message_sent and not self.paused:
            self.message_sent = True
            self.log.append(f"[Pijlwagen]: Afstand: {int(distance_to_car)}px - V2X bericht verzenden...")
            selected_mode = self.mode
            self.last_message_mode = selected_mode
            self.C_send_message_instant(selected_mode)
        
        # als de reactie tijd is afgelopen, wissel van baan
        if self.reaction_timer > 0.0:
            t = (self.reaction_duration - self.reaction_timer) / max(1e-6, self.reaction_duration)
            if self.target_speed is not None:
                self.speed = int(self.prev_speed + (self.target_speed - self.prev_speed) * t)
            self.flash = max(0.0, self.reaction_timer / self.reaction_duration)
            self.reaction_timer = max(0.0, self.reaction_timer - dt)
            if self.reaction_timer == 0.0:
                self.speed = self.prev_speed
                self.target_speed = None
                self.flash = 0.0

        # van baan wisselen
        if self.lane_switching:
            self.lane_switch_timer += dt
            if self.lane_switch_timer >= 1.0: 
                self.car_lane = self.target_lane
                self.lane_switching = False
                self.lane_switch_timer = 0.0
                self.signal_duration = 0.0
                self.signal_type = None
            else:
                t = self.lane_switch_timer / 1.0
                self.car_lane = self.car_lane + (self.target_lane - self.car_lane) * t * 0.1

        # blink de lampen van de auto
        if self.signal_type:
            self.signal_blink += dt
            if self.signal_blink >= self.signal_duration:
                self.signal_type = None
                self.signal_blink = 0.0

        # beweeg de auto als de simulatie niet op pauze staat
        if not self.paused:
            self.car_pos[0] -= self.speed * dt
        if self.car_pos[0] < -40:
            self.car_pos[0] = WINDOW_SIZE[0] + 40
            self.car_lane = 0 
            self.message_sent = False 
            self.can_return_to_center = True
        if self.car_pos[0] > WINDOW_SIZE[0] + 40:
            self.car_pos[0] = -40
            self.car_lane = 0  

        # beweeg en valideer het bericht als deze verstuurd is
        if self.packet_active:
            self.packet_progress += dt / max(1e-6, self.packet_duration)
            if self.packet_progress >= 1.0:
                self.packet_progress = 1.0
                self.packet_active = False
                self.C_validate_and_process_message()
            sx, sy = self.Pijlwagen_pos[0], self.Pijlwagen_pos[1]
            tx, ty = self.car_pos[0], self.car_pos[1] + self.car_lane
            self.packet_pos[0] = sx + (tx - sx) * self.packet_progress
            self.packet_pos[1] = sy + (ty - sy) * self.packet_progress

        # verzorg de reactie tijd
        if self.car_reaction_timer > 0.0:
            self.car_reaction_timer = max(0.0, self.car_reaction_timer - dt)
            self.car_flash = self.car_reaction_timer / max(1e-6, self.car_reaction_duration)
        else:
            self.car_flash = 0.0

    """de functie 'draw' regelt alle graphics van de simulatie"""
    def draw(self):
        # maak een leeg blauw scherm
        self.surface.fill((180, 210, 255))
        pygame.draw.rect(self.surface, (40, 40, 40), (0, 260, WINDOW_SIZE[0], 120))
        pygame.draw.line(self.surface, (255, 255, 255), (0, 260), (WINDOW_SIZE[0], 260), 3) 
        pygame.draw.line(self.surface, (255, 255, 255), (0, 380), (WINDOW_SIZE[0], 380), 3) 
        
        mark_w = 40
        for x in range(0, WINDOW_SIZE[0], mark_w * 2):
            pygame.draw.rect(self.surface, (220, 220, 100), (x + 10, 320, mark_w, 6))
        
        # bereken de positie van de pijlwagen
        ax, ay = self.Pijlwagen_pos
        base = pygame.Color(200, 50, 50)
        if self.flash > 0.01:
            flash_color = pygame.Color(240, 120, 30)
            mix = max(0.0, min(1.0, self.flash))
            col = pygame.Color(
                int(base.r + (flash_color.r - base.r) * mix),
                int(base.g + (flash_color.g - base.b) * mix),
                int(base.b + (flash_color.b - base.b) * mix),
            )
        else:
            col = base
        
        # teken de afbeelding van de pijlwagen op het scherm
        pijlwagen_img = self.assets['pijlwagen']
        img_rect = pijlwagen_img.get_rect(center=(ax, ay))
        self.surface.blit(pijlwagen_img, img_rect)
        lbl = self.font.render('Pijlwagen', True, (255, 0, 0))
        self.surface.blit(lbl, (ax - 20, ay - 60))

        # bereken de positie van de auto
        cx, cy = self.car_pos
        cy_adjusted = cy + self.car_lane
        max_lane_offset = 80 
        self.car_lane = max(0, min(max_lane_offset, self.car_lane)) 
        cy_adjusted = cy + self.car_lane
        
        # teken de auto op het scherm
        pygame.draw.rect(self.surface, (50, 100, 200), (cx - 22, cy_adjusted - 14, 44, 28), border_radius=6)
        pygame.draw.circle(self.surface, (20, 20, 20), (int(cx - 12), int(cy_adjusted + 16)), 6)
        pygame.draw.circle(self.surface, (20, 20, 20), (int(cx + 12), int(cy_adjusted + 16)), 6)
        lbl2 = self.font.render('Car', True, (255, 255, 255))
        self.surface.blit(lbl2, (cx - 12, cy_adjusted - 44))

        # teken de blinkende autolampen
        if self.signal_type:
            blink_on = (self.signal_blink % 0.6) < 0.3
            if blink_on:
                if self.signal_type == 'left':
                    pygame.draw.rect(self.surface, (255, 200, 0), (cx - 28, cy_adjusted - 8, 4, 16))
                elif self.signal_type == 'right':
                    pygame.draw.rect(self.surface, (255, 200, 0), (cx + 24, cy_adjusted - 8, 4, 16))

        if self.car_flash > 0.01:
            intensity = int(150 + 105 * (self.car_flash))
            left_light = (intensity, 10, 10)
            right_light = (intensity, 10, 10)
            pygame.draw.rect(self.surface, left_light, (cx + 6, cy_adjusted - 6, 6, 6))
            pygame.draw.rect(self.surface, right_light, (cx + 6, cy_adjusted + 0, 6, 6))

        # teken de tekst log onder in het scherm
        pygame.draw.rect(self.surface, (245, 245, 245), (10, 400, WINDOW_SIZE[0] - 20, 185))
        pygame.draw.rect(self.surface, (180, 180, 180), (10, 400, WINDOW_SIZE[0] - 20, 185), 2)
        
        # teken de tekst in de tekst log onder in het scherm
        log_start_line = max(0, len(self.log) - 8 - self.log_scroll_offset)
        for i, line in enumerate(self.log[log_start_line:log_start_line + 8]):
            t = self.font.render(line, True, (10, 10, 10))
            self.surface.blit(t, (18, 408 + i * 20))
        
        # geef de scroll optie bij meer dan 6 berichten
        if len(self.log) > 6:
            scroll_indicator = self.font.render(f"↑ {self.log_scroll_offset} older messages", True, (100, 100, 100))
            self.surface.blit(scroll_indicator, (WINDOW_SIZE[0] - 250, 410))

        # teken de snelheid van de auto op het scherm
        hud = self.font.render(f"Car speed: {int(self.speed)} px/s", True, (10, 10, 10))
        self.surface.blit(hud, (20, 70))
        
        # teken de afstand tussen de pijlwagen en de auto
        distance = abs(self.car_pos[0] - self.Pijlwagen_pos[0])
        distance_color = (255, 0, 0) if distance <= self.warning_distance else (0, 150, 0)
        distance_hud = self.font.render(f"Distance: {int(distance)}px", True, distance_color)
        self.surface.blit(distance_hud, (650, 70))
        
        # wisselen van baan
        if not self.can_return_to_center:
            lock_hud = self.font.render("Switching Lanes!", True, (255, 0, 0))
            self.surface.blit(lock_hud, (650, 90))

        # teken het verzonden bericht
        if self.packet_active:
            px, py = int(self.packet_pos[0]), int(self.packet_pos[1])
            pygame.draw.rect(self.surface, self.packet_color, (px - 10, py - 6, 20, 12))
            pygame.draw.polygon(self.surface, self.packet_color, [(px - 10, py - 6), (px + 10, py - 6), (px, py - 1)])
            pygame.draw.rect(self.surface, (100, 100, 100), (px - 10, py - 6, 20, 12), 1)

    """de functie '_start_reaction' regelt de tijd tussen het ontvangen bericht en de beslissing van de bestuurder"""
    def _start_reaction(self, intensity=0.5):
        self.prev_speed = self.speed
        self.target_speed = max(-400.0, self.prev_speed - int(self.prev_speed * (0.3 * intensity)))
        self.reaction_duration = 1.0 + 0.8 * intensity
        self.reaction_timer = self.reaction_duration
        self.flash = 1.0

    """de functie 'C_validate_and_process_message' valideert het bericht, print deze resultaten in de tekstbox en maakt een beslissing"""
    def C_validate_and_process_message(self):
        try:
            values = self.json_rapport[0]
            if len(values) > 0:
                self.log.append("== Values ==")
                for value in values:
                    self.log.append(f" -   {value[0]}: {value[1]}")

            validation = self.json_rapport[1]
            if len(validation) > 0:
                self.log.append("== Validation ==")
                for item in validation:
                    self.log.append(f" -   {item[0]}: {item[1]}")
        except Exception as e:
            print(f"ERROR: {e}")
            
        self._start_car_reaction()
        self.target_lane = 80
        self.lane_switching = True
        self.lane_switch_timer = 0.0
        
        self.can_return_to_center = False
        
        self.signal_type = 'right'
        self.log.append('[Voertuig]: wisselen van baan...')
        
        self.signal_duration = 1.5
        self.signal_blink = 0.0

    """de functie '_start_car_reaction' geeft aan dat het bericht is ontvangen"""
    def _start_car_reaction(self):
        self.car_reaction_timer = self.car_reaction_duration
        self.car_flash = 1.0
        self.log.append('[Voertuig]: bericht ontvangen.')

"""De class 'Visualizer' regelt alle graphics op het scherm."""
class Visualizer:
    # definieer de waardes van de visualisatie
    def __init__(self):
        self.assets = {}

    """de class 'start' zet alles klaar om de visualisatie te starten"""
    def start(self):
        # maak een window aan
        pygame.init()
        screen = pygame.display.set_mode(WINDOW_SIZE)
        
        # laad de afbeelding van de Pijlwagen in
        with importlib.resources.open_binary("CrashGuardIEEE.assets", "pijlwagen.png") as f:
            pijlwagen_img = pygame.image.load(f).convert_alpha()
            pijlwagen_img = pygame.transform.smoothscale(pijlwagen_img, (100, 100))
        self.assets['pijlwagen'] = pijlwagen_img

        # geef de window een titel
        pygame.display.set_caption('IEEE 1609.2 V2I Simulation - Secure Message Container')
        clock = pygame.time.Clock()
        font = pygame.font.SysFont('Arial', 18) # FONTSIZE

        # maak het hoofdmenu aan
        settings_active = True
        dropdown = Dropdown((20, 20, 180, 36), ['unsecure', 'signed', 'encrypted', 'enveloped'], font)
        start_btn = Button((220, 20, 120, 36), 'Start Sim', font)
        speed_label = font.render('Car Speed (px/s):', True, (10, 10, 10))
        initial_speed_input = "120"
        speed_input_rect = pygame.Rect(220, 80, 150, 36)
        
        send_btn = Button((220, 20, 120, 36), 'Send Message', font)
        speed_up_btn = Button((360, 20, 40, 36), '+', font)
        speed_down_btn = Button((410, 20, 40, 36), '-', font)
        pause_btn = Button((460, 20, 80, 36), 'Pause', font)
        back_to_menu_btn = Button((560, 20, 120, 36), 'Back to Menu', font)

        # start de simulatie
        sim = None
        
        running = True
        while running:
            dt = clock.tick(FPS) / 1000.0 # stelt het aantal frames per seconden in
            
            if settings_active:
                # Reageer op toetsenboord input
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        running = False
                    dropdown.handle_event(event)
                    if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                        if speed_input_rect.collidepoint(event.pos):
                            initial_speed_input = ""
                    if event.type == pygame.KEYDOWN:
                        if event.key == pygame.K_BACKSPACE:
                            initial_speed_input = initial_speed_input[:-1]
                        elif event.unicode.isdigit():
                            initial_speed_input += event.unicode
                    if start_btn.clicked(event):
                        try:
                            speed_val = float(initial_speed_input) if initial_speed_input else 120.0
                            speed_val = max(0.0, min(400.0, speed_val))
                            selected_mode = dropdown.options[dropdown.selected]
                            sim = Simulation(screen, font, selected_mode, self.assets)
                            sim.speed = speed_val
                            settings_active = False
                        except ValueError:
                            initial_speed_input = "120"
                
                # maak een nieuwe frame met alle tekst, knoppen en afbeeldingen
                screen.fill((180, 210, 255))
                title = font.render('V2I Simulation Settings', True, (10, 10, 10))
                screen.blit(title, (350, 25))
                
                mode_label = font.render('Security Mode:', True, (10, 10, 10))
                screen.blit(mode_label, (20, 20))
                
                screen.blit(speed_label, (20, 80))
                pygame.draw.rect(screen, (255, 255, 255), speed_input_rect)
                pygame.draw.rect(screen, (100, 100, 100), speed_input_rect, 2)
                speed_txt = font.render(initial_speed_input, True, (0, 0, 0))
                screen.blit(speed_txt, (225, 88))
                
                start_btn.draw(screen)
                dropdown.draw(screen)
                
                pygame.display.flip()
            else:
                # logica voor het afsluiten van de visualisatie
                for event in pygame.event.get():
                    if event.type == pygame.QUIT:
                        running = False
                    if send_btn.clicked(event):
                        mode = dropdown.options[dropdown.selected]
                        sim.C_send_message(mode)
                    if speed_up_btn.clicked(event):
                        sim.increase_speed(30.0)
                    if speed_down_btn.clicked(event):
                        sim.decrease_speed(30.0)
                    if pause_btn.clicked(event):
                        sim.toggle_pause()
                    if back_to_menu_btn.clicked(event):
                        settings_active = True
                        sim = None
                        continue
                    if event.type == pygame.MOUSEWHEEL:
                        if event.y > 0:
                            sim.log_scroll_offset = min(sim.log_scroll_offset + 1, max(0, len(sim.log) - 6))
                        else:
                            sim.log_scroll_offset = max(sim.log_scroll_offset - 1, 0)
                
                if sim is None:
                    continue

                # nieuwe frames laten zien op het scherm    
                sim.update(dt)

                sim.draw()
                
                send_btn.draw(screen)
                speed_up_btn.draw(screen)
                speed_down_btn.draw(screen)
                pause_btn.draw(screen)
                back_to_menu_btn.draw(screen)

                mode_txt = font.render(f"Mode: {dropdown.options[dropdown.selected]}", True, (10, 10, 10))
                screen.blit(mode_txt, (20, 100))
                paused_txt = font.render(f"Paused: {sim.paused}", True, (10, 10, 10))
                screen.blit(paused_txt, (20, 120))

                pygame.display.flip()