import os

def get_all_file_paths(directory):
    """
    Retrieve the relative paths of all files in the specified directory and its subdirectories.

    Args:
        directory (str): The directory to search for files.

    Returns:
        list: A list of relative paths for all files found.
    """
    file_paths = []  # List to store relative file paths

    # Walk through the directory and its subdirectories
    for root, _, files in os.walk(directory):
        for file in files:
            # Construct the relative path
            relative_path = os.path.relpath(os.path.join(root, file), directory)
            file_paths.append(relative_path)  # Add the relative path to the list

    return file_paths

if __name__ == '__main__':

    current_directory = os.getcwd()

    file_list = get_all_file_paths(current_directory)

    max_length = max(len(line) for line in file_list)
    for file in file_list:
        f = open(file, "r")
        lines = f.readlines()
        num_of_lines_contain_AND = 0
        for line in lines:
            if line.find("AND") != -1:
                num_of_lines_contain_AND += 1
        print(f"{' ' * (max_length - len(file)) + file}: #AND = {num_of_lines_contain_AND}")

