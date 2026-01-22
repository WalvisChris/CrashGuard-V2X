from typing import List
import curses
import os

KEY_UP = 450
KEY_DOWN = 456

class TerminalInterface:
    
    def __init__(self):
        self.COLORS = {
            "black": "\033[30m",
            "red": "\033[31m",
            "green": "\033[32m",
            "yellow": "\033[33m",
            "blue": "\033[34m",
            "magenta": "\033[35m",
            "cyan": "\033[36m",
            "white": "\033[37m",
            "bright_black": "\033[90m",
            "bright_red": "\033[91m",
            "bright_green": "\033[92m",
            "bright_yellow": "\033[93m",
            "bright_blue": "\033[94m",
            "bright_magenta": "\033[95m",
            "bright_cyan": "\033[96m",
            "bright_white": "\033[97m",
            "vs_yellow": "\033[38;2;214;194;139m",
            "vs_purple": "\033[38;2;137;71;252m"
        }
        self.RESET = "\033[0m"
        self.start_time = None
        self.last_timestamp = None
        self.frame = []
        self.COLOR_MAP = None

    def clear(self):
        os.system('cls')

    def text(self, text: str, color="white") -> None:
        color_code = self.COLORS.get(color.lower(), self.COLORS["white"])
        print(f"{color_code}{text}{self.RESET}")

    def input(self, prompt: str, color="white") -> str:
        color_code = self.COLORS.get(color.lower(), self.COLORS["white"])
        return input(f"{color_code}{prompt}{self.RESET}")

    def title(self, title: str, title_color="white", border_color="white"):
        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])

        WIDTH = len(title) + 10

        print(f"{border_color_code}{WIDTH*"="}{self.RESET}")
        print(f"{5*" "}{title_color_code}{title}{self.RESET}")
        print(f"{border_color_code}{WIDTH*"="}{self.RESET}")

    def textbox(self, title: str, title_color="white", items: List[str] = None, list_color="white", border_color="white", numbered: bool = False):
        if items is None:
            items = []

        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        list_color_code = self.COLORS.get(list_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])

        if numbered:
            numbered_items = [f"{i+1}. {item}" for i, item in enumerate(items)]
        else:
            numbered_items = items

        all_lines = [title] + numbered_items
        WIDTH = max(len(line) for line in all_lines) + 4  # +4 for padding

        print(f"{border_color_code}╭{'─' * WIDTH}╮{self.RESET}")

        print(f"{border_color_code}│ {title_color_code}{title.ljust(WIDTH - 2)}{border_color_code} │{self.RESET}")

        for sentence in numbered_items:
            print(f"{border_color_code}│ {list_color_code}{sentence.ljust(WIDTH - 2)}{border_color_code} │{self.RESET}")

        print(f"{border_color_code}╰{'─' * WIDTH}╯{self.RESET}")

    def demoLog(self, title: str, text: str, title_color="white", text_color="white"):
        title_color_code = self.COLORS.get(title_color.lower(), self.COLORS["white"])
        text_color_code = self.COLORS.get(text_color.lower(), self.COLORS["white"])
        print(f"[{title_color_code}{title}{self.RESET}]: {text_color_code}{text}{self.RESET}")

    def empty(self, lines: int = 1):
        print("\n" * lines, end="")
    
    KEY_COLORS_BY_DEPTH = [
        "blue"
    ]

    DATATYPE_COLORS_BY_DEPTH = [
        "bright_green",
        "vs_purple"
    ]

    VALUE_COLORS_BY_DEPTH = [
        "vs_yellow",
        "white"
    ]

    def UpperHeader(self, text: str, text_color="white", border_color="white"):
        text_color_code = self.COLORS.get(text_color.lower(), self.COLORS["white"])
        border_color_code = self.COLORS.get(border_color.lower(), self.COLORS["white"])
        print(f"{border_color_code}[{text_color_code}{text.upper()}{border_color_code}]{self.RESET}")
    
    def _is_last(self, lines, index, level):
        for next_line in lines[index + 1:]:
            next_level = len(next_line) - len(next_line.lstrip('>'))
            if next_level < level:
                return True
            if next_level == level:
                return False
        return True

    def printASN1(self, obj):
        KEY_COLOR = self.COLORS["blue"]
        OBJECT_COLOR = self.COLORS["vs_purple"]
        VAL_COLOR = self.COLORS["bright_cyan"]
        VALUE_COLOR = self.COLORS["bright_green"]

        text = obj.prettyPrint()

        lines = text.splitlines()
        new_lines = []
        for line in lines:
            leading_spaces = len(line) - len(line.lstrip(' '))
            new_line = '>' * leading_spaces + line.lstrip(' ')
            new_lines.append(new_line)
        text = "\n".join(new_lines)

        while "\n\n" in text:
            text = text.replace("\n\n", "\n")

        lines = text.splitlines()
        result = ""

        for i, line in enumerate(lines):
            level = len(line) - len(line.lstrip('>'))
            content = line[level:]

            if '=' in content:
                key, val = content.split('=', 1)

                if ':' in val:
                    content = f"{KEY_COLOR}{key}{self.RESET} = {OBJECT_COLOR}{val}{self.RESET}"
                else:
                    content = f"{VAL_COLOR}{key}{self.RESET} = {VALUE_COLOR}{val}{self.RESET}"

            if i == 0:
                result += content + "\n"
                continue

            last = self._is_last(lines, i, level)

            prefix = ""
            for l in range(1, level):
                if not self._is_last(lines, i, l):
                    prefix += " │ "
                else:
                    prefix += "   "

            branch = " └ " if last else " ├ "
            result += prefix + branch + content + "\n"

        print(result)

    def getASN1Text(self, obj):
        text = obj.prettyPrint()

        lines = text.splitlines()
        new_lines = []
        for line in lines:
            leading_spaces = len(line) - len(line.lstrip(' '))
            new_line = '>' * leading_spaces + line.lstrip(' ')
            new_lines.append(new_line)
        text = "\n".join(new_lines)

        while "\n\n" in text:
            text = text.replace("\n\n", "\n")

        lines = text.splitlines()
        result = []

        for i, line in enumerate(lines):
            level = len(line) - len(line.lstrip('>'))
            content = line[level:]

            # prefix (takken) toevoegen
            prefix = ""
            if i != 0:
                last = self._is_last(lines, i, level)
                prefix = ""
                for l in range(1, level):
                    if not self._is_last(lines, i, l):
                        prefix += " │ "
                    else:
                        prefix += "   "
                branch = " └ " if last else " ├ "
                prefix += branch
            
            line_render = []

            if prefix:
                line_render.append((prefix, "default"))

            if '=' in content:
                key, val = content.split('=', 1)
                if ':' in val:
                    line_render.append((key, "key"))
                    line_render.append((" = ", "default"))
                    line_render.append((val, "object"))
                else:
                    line_render.append((key, "val"))
                    line_render.append((" = ", "default"))
                    line_render.append((val, "value"))
            else:
                # geen '=', hele regel default
                line_render.append((content, "default"))

            result.append(line_render)

        return result
    
    def logValidation(self, cert_time=None, time=None, sig=None, cert=None, enc=None, pskId=None):     
        resultaten = [cert_time, time, sig, cert, enc, pskId]
        output = ["--", "--", "--", "--", "--", "--"]
        FAIL = self.COLORS["red"]
        SUCCES = self.COLORS["bright_green"]
        RESET = self.RESET
        
        for i, resultaat in enumerate(resultaten):
            if resultaat != None:
                output[i] = f"{SUCCES}Geldig!{RESET}" if resultaat else f"{FAIL}Ongeldig!{RESET}"

        self.text(text="────────────[Decoding Rapport]────────────")
        self.text(text=f"{"- Bericht Tijdcontrole":<30} : {output[1]}")
        self.text(text=f"{"- Certificaat Tijdcontrole":<30} : {output[0]}")
        self.text(text=f"{"- Signature Validatie":<30} : {output[2]}")
        self.text(text=f"{"- Certificate Validatie":<30} : {output[3]}")
        self.text(text=f"{"- Encryptie":<30} : {output[4]}")
        self.text(text=f"{"- PskId Validatie":<30} : {output[5]}")
        self.text(text="──────────────────────────────────────────")
        self.empty()
    
    def logDetailedValidation(self, certTimeMsg=None, timeMsg=None, sigMsg=None, certMsg=None, encMsg=None, pskIdMsg=None):
        resultaten = [certTimeMsg, timeMsg, sigMsg, certMsg, encMsg, pskIdMsg]
        output = ["--", "--", "--", "--", "--", "--"]
        LOG = self.COLORS['vs_yellow']
        RESET = self.RESET

        for i, resultaat in enumerate(resultaten):
            if resultaat != None:
                output[i] = f"{LOG}{resultaat}{RESET}"
        
        self.text(text="──────────────[Decoding Rapport Details]──────────────")
        self.text(text=f"{"- Bericht Tijdcontrole":<30} : {output[1]}")
        self.text(text=f"{"- Certificaat Tijdcontrole":<30} : {output[0]}")
        self.text(text=f"{"- Signature Validatie":<30} : {output[2]}")
        self.text(text=f"{"- Certificate Validatie":<30} : {output[3]}")
        self.text(text=f"{"- Encryptie":<30} : {output[4]}")
        self.text(text=f"{"- PskId Validatie":<30} : {output[5]}")
        self.text(text="──────────────────────────────────────────────────────")
        self.empty()

    def logFase4(self, headerTime=None, certTime=None, sig=None, certSig=None, pskId=None, enc=None):
        TRUE = self.COLORS["bright_green"]
        FALSE = self.COLORS["red"]
        TITLE = self.COLORS["vs_yellow"]
        RESET = self.RESET
        
        resultaten = [headerTime, certTime, sig, certSig, pskId, enc]

        self.text(text=f"───────────────[{TITLE}Decoding Rapport FASE4{RESET}]───────────────")
        for resultaat in resultaten:
            if resultaat:
                # resultaat = ["label", bool, "details"]
                label = resultaat[0]
                passed = f"{TRUE}{"(TRUE)":<7}{RESET}" if resultaat[1] else f"{FALSE}{"(FALSE)":<7}{RESET}"
                details = resultaat[2]
                self.text(f"{label:<25} {passed} : {details}")
        self.text(text="──────────────────────────────────────────────────────")
        self.empty()
    
    def logTimes(self, times: List[tuple], total: float):
        LOG = self.COLORS['bright_cyan']
        TOTAL = self.COLORS['bright_green']
        RESET = self.RESET
        self.text(text=f"{"TIMESTAMP":<40} : {"TIME":>10}")
        self.text(text=("=" * 56)) # 40 text + 10 ms + 6 display
        for time, text in times:
            self.text(text=f"{text:<40} : {LOG}{time:>10.4f} ms{RESET}")
        self.text(text=("=" * 56)) # 40 text + 10 ms + 6 display
        self.text(text=f"{TOTAL}{"TOTAL":<40} : {total:>10.4f} ms{RESET}")
        self.empty()

    def menu(self, choices, title=None):
        return curses.wrapper(lambda stdscr: self.cursesMenu(stdscr, choices, title))

    def simpleTitle(self, title):
        return [[(title, "default")]]

    def rbt2xterm(self, r, g, b):
        r6 = int(r / 256 * 6)
        g6 = int(g / 256 * 6)
        b6 = int(b / 256 * 6)
        return 16 + 36*r6 + 6*g6 + b6

    def cursesMenu(self, stdscr, choices, title=None):
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)

        # kleurensysteem initialiseren
        curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLUE, -1)              # key
        curses.init_pair(2, self.rbt2xterm(137, 71, 252), -1)   # object
        curses.init_pair(3, curses.COLOR_CYAN, -1)              # val
        curses.init_pair(4, curses.COLOR_GREEN, -1)             # value

        self.COLOR_MAP = {
            "default": 0,
            "key": 1,
            "object": 2,
            "val": 3,
            "value": 4
        }

        selected = 0

        import wcwidth  # voor Unicode breedte van tekens

        while True:
            stdscr.clear()
            max_rows, max_cols = stdscr.getmaxyx()

            # -------------------------------
            # Titel tekenen (multi-line, wrapped)
            # -------------------------------
            start_row = 0
            if title:
                screen_row = 0
                for line_render in title:
                    col = 0
                    for text, color_key in line_render:
                        # check of we niet buiten scherm rijen tekenen
                        if screen_row >= max_rows:
                            break
                        # crop text zodat we niet buiten scherm kolommen gaan
                        available_space = max_cols - col
                        if available_space <= 0:
                            screen_row += 1
                            col = 0
                            available_space = max_cols
                        # text inkorten als het te breed is
                        display_text = text
                        if wcwidth.wcswidth(display_text) > available_space:
                            display_text = display_text[:available_space]
                        stdscr.addstr(screen_row, col, display_text, curses.color_pair(self.COLOR_MAP[color_key]))
                        col += wcwidth.wcswidth(display_text)

                        # wrap als we over max_cols heen gaan
                        while col >= max_cols:
                            col -= max_cols
                            screen_row += 1
                    screen_row += 1  # volgende regel
                start_row = screen_row + 1  # menu start onder de titel

            # -------------------------------
            # Menu tekenen
            # -------------------------------
            for i, choice in enumerate(choices):
                row = start_row + i
                if row >= max_rows:  # veilige check
                    break
                
                # visual fix
                prefix = "> " if i == selected else ""

                # crop te lange keuzes
                display_choice = (prefix + choice)[:max_cols]
                if i == selected:
                    stdscr.attron(curses.A_REVERSE)
                    stdscr.addstr(row, 0, display_choice)
                    stdscr.attroff(curses.A_REVERSE)
                else:
                    stdscr.addstr(row, 0, display_choice)

            # -------------------------------
            # Input
            # -------------------------------
            key = stdscr.getch()
            if key == KEY_UP and selected > 0:
                selected -= 1
            elif key == KEY_DOWN and selected < len(choices) - 1:
                selected += 1
            elif key == ord("\n"):
                return selected + 1

            stdscr.refresh()