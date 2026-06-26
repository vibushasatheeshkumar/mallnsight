import os
import mimetypes

def get_metadata(file_path):

    file_size = os.path.getsize(file_path)

    file_name = os.path.basename(file_path)

    mime_type = mimetypes.guess_type(file_path)[0]

    extension = os.path.splitext(file_name)[1]

    return {
        "name": file_name,
        "size": round(file_size / 1024, 2),
        "extension": extension,
        "mime": mime_type
    }