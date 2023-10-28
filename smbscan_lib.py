"""
Helper functions
"""

import logging

def load_file(input_file: str):
    """
    Function to open a file and read a list of usernames.

    Parameters
        input_file: str, path to and filename of text file containing usernames or passwords

    File format:
        Function expects one username or password per line.

    Returns:
        List of usernames or passwords in string format.
    """

    try:
        with open(input_file, 'r', encoding='utf-8') as input_data:
            # read entire file in one go and strip newlines and spaces from the end of each line
            usernames = [line.rstrip() for line in input_data]
        return usernames
    except TypeError as type_error:
        logging.error("Missing file/path input parameter.\n")
        raise type_error
    except FileNotFoundError as file_not_found:
        logging.error("Given file does not exist.\n")
        raise file_not_found
