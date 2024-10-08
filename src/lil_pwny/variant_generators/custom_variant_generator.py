from typing import List
from datetime import datetime


class CustomVariantGenerator:
    """ Enhances the custom password with additional variations
    """

    def __init__(self, min_password_length: int = 8):
        self.min_password_length = min_password_length

    def _deduplicate(self, password_list: List) -> List:
        """ Remove duplicates from the given list
        """

        return list(set(password_list))

    def _remove_too_short(self, password_list: List) -> List:
        """ Remove passwords that do not match the length requirements
        """

        return [password for password in password_list if len(password) >= self.min_password_length]

    def _add_leet_speak(self, password: str) -> List[str]:
        """ Add leetspeak variations to a single password"""

        leet_speak_mappings = {
            'a': ['4', '@'],
            'b': ['8'],
            'e': ['3'],
            'g': ['6'],
            'i': ['1', '!'],
            'l': ['1'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'z': ['2'],
        }

        def _generate_variations(word: str, index: int = 0) -> List[str]:
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

        return _generate_variations(password)

    def _capitalise_first_character(self, password_list: List) -> List:
        """ Capitalise the first letter of each password in the list
        """

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
        """ Append years from 1950 to ten years greater than the current year to each password in the list
        """

        current_year = datetime.now().year
        end_year = current_year
        years = [str(year) for year in range(1950, end_year + 1)]
        return [password + year for password in password_list for year in years]

    def _append_special_characters(self, password_list: List) -> List:
        """ Append special characters commonly used in passwords to the end of each password in the list
        """

        special_characters = ['!', '@', '#', '$', '%', '&', '*', '?']
        return [password + char for password in password_list for char in special_characters]

    def enhance_password(self, password: str) -> List:
        """ Enhance a plaintext password list with additional variations

        Args:
            password: The custom password to enhance
        Returns:
            Enhanced list of passwords
        """

        enhanced_list = self._add_leet_speak(password)
        enhanced_list += self._capitalise_first_character(enhanced_list)
        enhanced_list += self._pad_password(enhanced_list)
        enhanced_list += self._append_years(enhanced_list)
        enhanced_list += self._append_special_characters(enhanced_list)
        return self._deduplicate(self._remove_too_short(enhanced_list))
