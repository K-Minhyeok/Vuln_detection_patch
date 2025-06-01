import argparse

def parse_arg():
    parser = argparse.ArgumentParser(description="ELF(.bin) file vulnerable detection")
    parser.add_argument("-j", "--json", action="store_true", help="Store results with .json file")
    return parser.parse_args() 