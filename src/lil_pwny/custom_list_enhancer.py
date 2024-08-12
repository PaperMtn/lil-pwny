from typing import List
from datetime import datetime
import multiprocessing as mp


class CustomListEnhancer:
    """ Enhances the custom password list with additional variations """

    def __init__(self, min_password_length: int = 8):
        self.min_password_length = min_password_length

    def _deduplicate(self, password_list: List) -> List:
        """ Remove duplicates from the list """
        return list(set(password_list))

    def _add_leet_speak(self, password_list: List) -> List:
        """ Add leet speak variations to the list """
        leet_speak_mappings = {
            'a': ['4', '@'], 'b': ['8'], 'c': ['<'], 'e': ['3'],
            'g': ['6'], 'h': ['#'], 'i': ['1', '!'], 'l': ['1'],
            'o': ['0'], 's': ['5', '$'], 't': ['7'], 'z': ['2'],
        }

        def _generate_variations(word: str, index: int = 0):
            if index == len(word):
                return [word]
            current_char = word[index]
            variations = _generate_variations(word, index + 1)
            if current_char.lower() in leet_speak_mappings:
                additional_variations = []
                for leet_char in leet_speak_mappings[current_char.lower()]:
                    for variation in variations:
                        additional_variations.append(variation[:index] + leet_char + variation[index + 1:])
                variations.extend(additional_variations)
            return variations

        return [variation for password in password_list for variation in _generate_variations(password)]

    def _capitalise_first_character(self, password_list: List) -> List:
        """ Capitalise the first letter of each password """
        return [password.capitalize() for password in password_list]

    def _pad_password(self, password_list: List) -> List:
        """ Pad the password with the original word and additional characters to meet the minimum password length
            Characters include alphanumeric characters and special characters
        """
        output_list = []
        for password in password_list:
            if len(password) < self.min_password_length:
                repeated_password = (password * ((self.min_password_length // len(password)) + 1))[
                                    :self.min_password_length]
                padding_length = self.min_password_length - len(password)
                lowercase_padding = ''.join(chr(97 + i % 26) for i in range(padding_length))
                uppercase_padding = ''.join(chr(65 + i % 26) for i in range(padding_length))
                numeric_padding = ''.join(chr(49 + i % 10) for i in range(padding_length))
                output_list.append(repeated_password)
                output_list.append(password + lowercase_padding)
                output_list.append(password + uppercase_padding)
                output_list.append(password + numeric_padding)
        return output_list

    def _append_years(self, password_list: List) -> List:
        """ Append years from 1950 to ten years greater than the current year to each password in the list """
        current_year = datetime.now().year
        end_year = current_year + 10
        years = [str(year) for year in range(1950, end_year + 1)]
        return [password + year for password in password_list for year in years]

    def _append_special_characters(self, password_list: List) -> List:
        """ Append special characters commonly used in passwords to the end of each password in the list """
        special_characters = ['!', '@', '#', '$', '%', '&', '*', '?']
        return [password + char for password in password_list for char in special_characters]

    def enhance_list(self, password_list: List) -> List:
        """ Enhance a plaintext password list with additional variations """
        with mp.Pool() as pool:
            chunks = [password_list[i::mp.cpu_count()] for i in range(mp.cpu_count())]
            results = pool.map(self._enhance_chunk, chunks)
        enhanced_list = [item for sublist in results for item in sublist]
        return self._deduplicate(enhanced_list)

    def _enhance_chunk(self, password_list: List) -> List:
        """ Helper method to enhance a chunk of passwords """
        enhanced_list = password_list
        enhanced_list += self._add_leet_speak(password_list)
        enhanced_list += self._capitalise_first_character(enhanced_list)
        enhanced_list += self._pad_password(enhanced_list)
        enhanced_list += self._append_years(enhanced_list)
        enhanced_list += self._append_special_characters(enhanced_list)
        return enhanced_list


def main():
    password_list = ['ocado', '123456']
    enhancer = CustomListEnhancer(15)
    enhanced_list = enhancer.enhance_list(password_list)
    print(enhanced_list)
    print(len(enhanced_list))


if __name__ == '__main__':
    main()
