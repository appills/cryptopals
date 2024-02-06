class PlaintextScoreCalculator:
    def __init__(self, char_set: str, encoding='ascii'):
        self.char_set = bytes(char_set, encoding)

    def calculate_scores(self, plaintexts):
        scored_entries = []
        for idx, text in enumerate(plaintexts):
            score = self.score_bytes(text)
            scored_entries.append((score, idx, text))
        scored_entries.sort(key=lambda tup: tup[0], reverse=True)
        return scored_entries
    
    def score_bytes(self, entry):
        total = len(entry)
        score = 0
        for b in entry:
            if b in self.char_set:
                score += 1
        return score / total