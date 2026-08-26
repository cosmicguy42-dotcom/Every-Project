
class Solution:
    def lengthOfLastWord(self, s: str) -> int:
        world = s.split()

        return len(world[-1])


input_str = "Hello World"
sol = Solution()
rslt = sol.lengthOfLastWord(input_str)

print(f"The lenght of last world is {rslt}")

        