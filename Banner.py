import typer


def banner():

    banner = r"""  ____                  _        __  __           _            
 / ___|_ __ _   _ _ __ | |_ ___ |  \/  | __ _ ___| |_ ___ _ __ 
| |   | '__| | | | '_ \| __/ _ \| |\/| |/ _` / __| __/ _ \ '__|
| |___| |  | |_| | |_) | || (_) | |  | | (_| \__ \ ||  __/ |   
 \____|_|   \__, | .__/ \__\___/|_|  |_|\__,_|___/\__\___|_|   
            |___/|_|                                           
"""

    typer.secho(banner, fg=typer.colors.GREEN)
