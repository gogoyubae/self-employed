<template>
  <div>
    <AssetHeader />
    <div class="container streg-con">
      <div class="streg-h3">
        <h3>내 가게 등록</h3>
      </div>
      <div class="mb-8">
        <h4 class="streg-h4">가게 정보</h4>
        <p class="straeg-p">등록할 가게 주소를 입력해 주세요</p>
        <div class="col-sm-4 d-inline-flex align-items-center">
          <input
            type="text"
            class="form-control me-2 mb-3"
            placeholder="도로명, 지번, 건물명 검색"
          />
        </div>
        <button class="btn btn-primary">주소검색</button>
        <div class="col-sm-6">
          <input type="text" class="form-control" placeholder="상세주소" />
        </div>
      </div>
      <div class="mb-8">
        <h4 class="streg-h4">가게 정보</h4>
        <p class="mb-2">가게 권리금 및 투자액을 입력해 주세요</p>
        <div class="d-flex">
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">권리금</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2">
            <h5 class="mb-2">총 투자액</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
        </div>
      </div>
      <div class="mb-8">
        <h4 class="streg-h4 mb">매출 정보</h4>
        <p class="mb-2">가게 월 매출 정보와 마진율을 입력해 주세요</p>
        <div class="d-flex">
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">마진율</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">손익 분기점</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
        </div>
      </div>
      <div class="mb-8">
        <h4 class="streg-h4 mb">경비</h4>
        <p class="mb-2">가게 공과금 및 기타 비용을 입력해 주세요</p>
        <div class="d-flex">
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">입점비용</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">월인건비</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">공과비용</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">기타비용</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
        </div>
      </div>
      <div class="mb-8">
        <h4 class="streg-h4 mb">종합 정보</h4>
        <p class="mb-2">상위 입력값을 바탕으로 계산된 정보를 보여드립니다.</p>
        <div class="d-flex">
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">매출 이익</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">경비합계</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">월수익</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
          <div class="col-sm-2 me-8">
            <h5 class="mb-2">권리금 회수기간</h5>
            <input type="text" class="form-control me-2 mb-3" />
          </div>
        </div>
      </div>
      <div class="d-flex justify-content-center">
        <button class="btn btn-primary streg-btn">가게 정보 등록하기</button>
      </div>
    </div>
  </div>
</template>

<script>
import AssetHeader from '@/components/asset/AssetHeader.vue';
</script>

<style>
.streg-con {
  padding: 0px 150px 0px 150px;
}
.streg-h3 {
  text-align: center;
  margin-bottom: 30px;
}
.col-sm-4 {
  display: inline-flex; /* 인라인 플렉스 박스 */
  align-items: center; /* 수직 정렬 */
}

.straeg-p {
  margin-bottom: 10px;
}

.streg-btn {
  width: 20%;
}
</style>
