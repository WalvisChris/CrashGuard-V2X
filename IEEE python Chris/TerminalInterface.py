from typing import List
import os

COLORS = {
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
    "bright_white": "\033[97m"
}

RESET = "\033[0m"

class TerminalInterface:
    def clear(self):
        os.system('cls')

    def text(self, text: str, color="white") -> None:
        color_code = COLORS.get(color.lower(), COLORS["white"])
        print(f"{color_code}{text}{RESET}")

    def input(self, prompt: str, color="white") -> str:
        color_code = COLORS.get(color.lower(), COLORS["white"])
        return input(f"{color_code}{prompt}{RESET}")

    def title(self, title: str, title_color="white", border_color="white"):
        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        border_color_code = COLORS.get(border_color.lower(), COLORS["white"])
        
        WIDTH = len(title) + 10
        
        print(f"{border_color_code}{WIDTH*"="}{RESET}")
        print(f"{5*" "}{title_color_code}{title}{RESET}")
        print(f"{border_color_code}{WIDTH*"="}{RESET}")
    
    def textbox(self, title: str, title_color="white", items: List[str] = None, list_color="white", border_color="white", numbered: bool = False):
        if items is None:
            items = []

        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        list_color_code = COLORS.get(list_color.lower(), COLORS["white"])
        border_color_code = COLORS.get(border_color.lower(), COLORS["white"])

        if numbered:
            numbered_items = [f"{i+1}. {item}" for i, item in enumerate(items)]
        else:
            numbered_items = items

        all_lines = [title] + numbered_items
        WIDTH = max(len(line) for line in all_lines) + 4  # +4 for padding

        print(f"{border_color_code}╭{'─' * WIDTH}╮{RESET}")

        print(f"{border_color_code}│ {title_color_code}{title.ljust(WIDTH - 2)}{border_color_code} │{RESET}")

        for sentence in numbered_items:
            print(f"{border_color_code}│ {list_color_code}{sentence.ljust(WIDTH - 2)}{border_color_code} │{RESET}")

        print(f"{border_color_code}╰{'─' * WIDTH}╯{RESET}")

    def demoLog(self, title: str, text: str, title_color="white", text_color="white"):
        title_color_code = COLORS.get(title_color.lower(), COLORS["white"])
        text_color_code = COLORS.get(text_color.lower(), COLORS["white"])
        print(f"[{title_color_code}{title}{RESET}]:\n{text_color_code}{text}{RESET}")
    
    def empty(self, lines: int = 1):
        print(lines*"\n")
