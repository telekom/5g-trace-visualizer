import os.path


def add_folder_to_file_list(csv_file_str: str, folder: str) -> str:
    if folder is None or folder == '':
        return csv_file_str
    if csv_file_str is None or csv_file_str == '':
        return csv_file_str
    input_files = csv_file_str.split(',')
    output_files = [os.path.join(folder, f) for f in input_files]
    output_files_str = ','.join(output_files)
    return output_files_str
