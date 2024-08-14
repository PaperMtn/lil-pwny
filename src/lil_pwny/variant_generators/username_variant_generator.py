from typing import Dict, List


class UsernameVariantGenerator:

    def generate_variations(self, ad_user_list: Dict[str, List[str]]) -> List[str]:
        """ Generates variations of usernames based on specific rules.
            - All uppercase
            - All lowercase
            - Remove dot "."
            - camelCase
            - PascalCase

        Args:
            ad_user_list: A dictionary where keys are NTLM hashes and values are lists of usernames.
        Returns:
            List: A list of generated username variations.
        """

        variations = []

        for ntlm_hash, usernames in ad_user_list.items():
            for uname in usernames:
                if '.' in uname:
                    split_uname = uname.split('.')

                    if len(split_uname) > 1:
                        camel_uname = split_uname[0].lower() + ''.join(part.capitalize() for part in split_uname[1:])
                        variations.append(camel_uname)

                        pascal_uname = ''.join(part.capitalize() for part in split_uname)
                        variations.append(pascal_uname)

                    stripped_uname = uname.replace('.', '')
                    variations.append(stripped_uname.upper())
                    variations.append(stripped_uname.lower())

                variations.append(uname.upper())
                variations.append(uname.lower())

        return variations
