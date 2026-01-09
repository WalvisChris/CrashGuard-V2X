from typing import List
import os

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

    def logValidation(self, cert_time=None, time=None, sig=None, cert=None, enc=None, pskId=None):     
        resultaten = [cert_time, time, sig, cert, enc, pskId]
        output = ["--", "--", "--", "--", "--", "--"]
        FAIL = self.COLORS["red"]
        SUCCES = self.COLORS["bright_green"]
        RESET = self.RESET
        
        for i, resultaat in enumerate(resultaten):
            if resultaat != None:
                output[i] = f"{SUCCES}Geldig!{RESET}" if resultaat else f"{FAIL}Ongeldig!{RESET}"

        self.text(text="────────────[Encoding Rapport]────────────")
        self.text(text=f"{"- Bericht Tijdcontrole":<30} : {output[1]}")
        self.text(text=f"{"- Certificate Tijdcontrole":<30} : {output[0]}")
        self.text(text=f"{"- Signature Validatie":<30} : {output[2]}")
        self.text(text=f"{"- Certificate Validatie":<30} : {output[3]}")
        self.text(text=f"{"- Encryptie":<30} : {output[4]}")
        self.text(text=f"{"- PskId Validatie":<30} : {output[5]}")
        self.text(text="────────────────────────────────────────────────────")
        self.empty()
    
    def logDetailedValidation(self, certTimeMsg=None, timeMsg=None, sigMsg=None, certMsg=None, encMsg=None, pskIdMsg=None):
        resultaten = [certTimeMsg, timeMsg, sigMsg, certMsg, encMsg, pskIdMsg]
        output = ["--", "--", "--", "--", "--", "--"]
        LOG = self.COLORS['bright_cyan']
        RESET = self.RESET

        for i, resultaat in enumerate(resultaten):
            if resultaat != None:
                output[i] = f"{LOG}{resultaat}{RESET}"
        
        self.text(text="─────────────[Encoding Rapport Details]─────────────")
        self.text(text=f"{"- Bericht Tijdcontrole":<30} : {output[1]}")
        self.text(text=f"{"- Certificate Tijdcontrole":<30} : {output[0]}")
        self.text(text=f"{"- Signature Validatie":<30} : {output[2]}")
        self.text(text=f"{"- Certificate Validatie":<30} : {output[3]}")
        self.text(text=f"{"- Encryptie":<30} : {output[4]}")
        self.text(text=f"{"- PskId Validatie":<30} : {output[5]}")
        self.text(text="────────────────────────────────────────────────────")
        self.empty()
    
    def logTimes(self, times: List[tuple], total: float):
        LOG = self.COLORS['bright_cyan']
        TOTAL = self.COLORS['bright_green']
        RESET = self.RESET
        self.text(text=f"{"TIMESTAMP":<40} : {"TIME":>10}")
        self.text(text=("=" * 56)) # 40 text + 10 ms + 6 display
        for text, time in times:
            self.text(text=f"{text:<40} : {LOG}{time:>10.4f} ms{RESET}")
        self.text(text=("=" * 56)) # 40 text + 10 ms + 6 display
        self.text(text=f"{TOTAL}{"TOTAL":<40} : {total:>10.4f} ms{RESET}")
        self.empty()