
class Solution:
    def reverseEvenWords(self, s: str) -> list[str]:
        
        data = []
        word = s.split()
        
        for w in word:
            if len(word) % 2 == 0:
                data.append(w[::-1])
            else:
                data.append(w)
        return data



input_str = "Python is very cool"

sol = Solution()
rslt = sol.reverseEvenWords(input_str)

print(f"Final Output: {rslt}")
# Expected output: ['nohtyP', 'is', 'yrev', 'looc']