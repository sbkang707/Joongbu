"""요일별 매출 평균 분석 실습

- None  : 휴무 등으로 기록이 없는 날 → 계산에서 제외
- 0     : 영업했지만 매출이 없었던 날 → 유효한 값이므로 계산에 포함
"""

sales = {
    "월": 12000,
    "화": None,
    "수": 18000,
    "목": 8000,
    "금": 0,
    "토": 22000,
    "일": None,
}

# 도전 2: 모든 값을 None으로 바꿔 보세요.
# sales = {day: None for day in sales}

# None만 제외 (0은 유효한 매출이므로 남긴다)
valid = {day: amount for day, amount in sales.items() if amount is not None}
excluded = [day for day, amount in sales.items() if amount is None]

if not valid:
    print("유효한 매출이 없습니다")
else:
    total = sum(valid.values())
    average = total / len(valid)

    # 도전 1: >= 를 > 로 바꾸면 결과는 수·토, 2일
    above = [day for day, amount in valid.items() if amount >= average]

    print(f"유효 {len(valid)}일 / 제외 {len(excluded)}일")
    print(f"합계 {total:,}원 / 평균 {average:,.0f}원")
    print(f"평균 이상: {'·'.join(above)} ({len(above)}일)")

# 비교해 보기:
# 금요일의 0원을 빼면 평균은 60,000 / 4 = 15,000원이 됩니다.
# 하지만 금요일은 '영업했는데 매출이 0원'인 실제 기록입니다.
# None(기록 없음)과 달리 0은 의미 있는 데이터이므로, 빼 버리면
# 평균이 실제보다 부풀려집니다. 그래서 금요일은 남겨야 합니다.
