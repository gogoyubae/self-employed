<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <div class="row">
        <div class="">
          <!-- Product details-->
          <div class="offset-xl-1">
            <div class="d-none d-md-block" style="margin-top: -90px"></div>
            <div class="position-md-sticky top-0 ps-md-4 ps-lg-5 ps-xl-0">
              <div class="d-none d-md-block" style="padding-top: 90px"></div>
              <h1 class="d-none d-md-inline-block pb-1 mb-2">
                혁신성장촉진자금
              </h1>
              <hr />
              <div class="row">
                <div
                  class="col-4 d-flex align-items-center justify-content-center"
                >
                  <span>
                    <i
                      class="fa-solid fa-calendar-days"
                      style="font-size: 50px"
                    ></i>
                  </span>
                  <span class="text ms-3">
                    <span style="color: gray">신청기간</span> <br />
                    <strong>2024.04.01 ~ 자산 소진시 마감</strong>
                  </span>
                </div>
                <div
                  class="col-4 d-flex align-items-center justify-content-center"
                >
                  <span>
                    <i class="fa-solid fa-coins" style="font-size: 50px"></i>
                  </span>
                  <span class="text ms-3">
                    <span style="color: gray">금리</span> <br />
                    <strong style="color: brown">3.83%</strong>
                  </span>
                </div>
                <div
                  class="col-4 d-flex align-items-center justify-content-center"
                >
                  <span>
                    <i class="fa-solid fa-won-sign" style="font-size: 50px"></i>
                  </span>
                  <span class="text ms-3">
                    <span style="color: gray">가산금리</span> <br />
                    <strong style="color: brown">0.4%</strong>
                  </span>
                </div>
              </div>

              <hr />
              <h3>상품 안내</h3>
              <hr />

              <h4>1. 지원대상</h4>
              <p>
                (혁신형) 수출 소상공인, 2년 연속 매출 10% 이상 신장, 스마트공장
                도입 소상공인, 사회적경제기업, 강한소상공인·로컬크리에이터<br />
                (일반형) 스마트기술·온라인활용, 백년소공인(백년가게) 등
                혁신형소상공인, 신사업창업사관학교 수료생
              </p>

              <hr />

              <h4>2. 접수기간</h4>
              <p>2024년 4월 8일(월) 9시 ~ 2024년 4월 12일(금) 18시</p>

              <hr />

              <h4>3. 지원내용</h4>
              <p>
                제품생산 비용 및 기업경영에 필요한 운전자금과 기계 설비 도입
                등에 소요되는 시설자금을 지원합니다.<br /><br />
                <strong>대출금리:</strong> 정책자금 기준금리 + 0.4%p
                (변동금리)<br />
                <strong>대출기간:</strong> 운전자금 5년(거치기간 2년 포함),
                시설자금 8년(거치기간 3년 포함)<br />
                <strong>대출한도:</strong> (혁신형) 운전 2억원, 시설 10억원
                (일반형) 운전 1억원, 시설 5억원<br />
                <strong>융자방식:</strong> 소진공을 통한 직접대출
              </p>

              <hr />

              <h4>4. 신청방법</h4>
              <p>
                소상공인정책자금 사이트 (<a
                  href="https://ols.sbiz.or.kr"
                  target="_blank"
                  >https://ols.sbiz.or.kr</a
                >)에서 온라인 접수
              </p>
              <hr />
            </div>
          </div>
        </div>
        <!-- <div class="col-6">
          <h2>대출 계산기</h2>
        </div> -->
      </div>
    </div>
  </div>
</template>
<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
import LoanHeader from '@/components/infoplaza/PersonalLoanHeader.vue';
</script>

<style></style>
