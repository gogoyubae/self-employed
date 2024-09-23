<template>
  <div>
    <img src="@/assets/img/community/talking.png" class="result-image mb-10">
    <div class="container">
        <div class="result-text">커뮤니티</div>
        <div class="overlay">
          <div class="overlay-text">
              <div class="text-center d-flex justify-content-center">
                  <div class="d-flex w-100" style="max-width: 1000px;">
                      <div class="flex-item">
                          <a href="#"><h4>음식/음료</h4></a>
                      </div>
                      <div class="flex-item">
                          <a href="#"><h4>유통</h4></a>
                      </div>
                      <div class="flex-item">
                          <a href="#"><h4>패션/뷰티</h4></a>
                      </div>
                      <div class="flex-item">
                          <a href="#"><h4>의료</h4></a>
                      </div>
                      <div class="flex-item">
                          <a href="#"><h4>여가/오락</h4></a>
                      </div>
                  </div>
              </div>
          </div>
      </div>
      <div class="flex-fill overflow-y-lg-auto scrollbar bg-body rounded-top-4 rounded-top-start-lg-4 rounded-top-end-lg-0 border-top border-lg shadow-2">
        <main class="container-fluid px-6 pb-10">
          <header class="py-4 border-bottom">
            <div class="row align-items-center">
              <div class="col">
                <div class="d-flex align-items-center gap-4">
                  <div>
                    <button type="button" class="btn-close text-xs" aria-label="Close"></button>
                  </div>
                  <div class="vr opacity-20 my-1"></div>
                  <h1 class="h4 ls-tight">Add a new asset</h1>
                </div>
              </div>
              <div class="col-auto d-none d-md-block">
                <div class="hstack gap-2 justify-content-end">
                  <a href="#!" class="text-sm text-muted text-primary-hover fw-semibold me-2 d-none d-md-block">
                    <i class="bi bi-question-circle-fill"></i>
                    <span class="d-none d-sm-inline ms-2">Need help?</span>
                  </a>
                  <button type="button" class="btn btn-sm btn-neutral">
                    <span>Save and create another</span>
                  </button>
                  <button type="button" class="btn btn-sm btn-primary">
                    <span>Save</span>
                  </button>
                </div>
              </div>
            </div>
          </header>
          <div class="row align-items-center g-3 mt-6">
            <div class="col-md-2">
              <label class="form-label mb-0">Asset name</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <input type="text" class="form-control" placeholder="Asset name" />
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3">
            <div class="col-md-2">
              <h6 class="fw-semibold">Description</h6>
            </div>
            <div class="col-md-8 col-xl-5">
              <label class="visually-hidden">Description</label>
              <textarea class="form-control" placeholder="Asset description ..." rows="2"></textarea>
              <span class="d-block mt-2 text-sm text-muted">Make it unique.</span>
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3">
            <div class="col-md-2">
              <label class="form-label mb-0">Select type</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <div class="d-flex gap-3 scrollable-x">
                <div class="form-item-checkable">
                  <input class="form-item-check" type="radio" name="asset-type" id="asset-type-crypto" checked="checked">
                  <label class="form-item cursor-pointer" for="asset-type-crypto">
                    <span class="form-item-click d-inline-flex flex-column gap-3 align-items-center justify-content-center form-control w-rem-24 h-rem-24 text-center text-muted">
                      <i class="bi bi-currency-bitcoin text-xl"></i>
                      <span class="fw-semibold text-xs">Crypto</span>
                    </span>
                  </label>
                </div>
                <div class="form-item-checkable">
                  <input class="form-item-check" type="radio" name="asset-type" id="asset-type-stock">
                  <label class="form-item cursor-pointer" for="asset-type-stock">
                    <span class="form-item-click d-inline-flex flex-column gap-3 align-items-center justify-content-center form-control w-rem-24 h-rem-24 text-center text-muted">
                      <i class="bi bi-diagram-3 text-xl"></i>
                      <span class="fw-semibold text-xs">Stock</span>
                    </span>
                  </label>
                </div>
                <div class="form-item-checkable">
                  <input class="form-item-check" type="radio" name="asset-type" id="asset-type-currency">
                  <label class="form-item cursor-pointer" for="asset-type-currency">
                    <span class="form-item-click d-inline-flex flex-column gap-3 align-items-center justify-content-center form-control w-rem-24 h-rem-24 text-center text-muted">
                      <i class="bi bi-coin text-xl"></i>
                      <span class="fw-semibold text-xs">Currency</span>
                    </span>
                  </label>
                </div>
                <div class="form-item-checkable">
                  <input class="form-item-check" type="radio" name="asset-type" id="asset-type-commodity">
                  <label class="form-item cursor-pointer" for="asset-type-commodity">
                    <span class="form-item-click d-inline-flex flex-column gap-3 align-items-center justify-content-center form-control w-rem-24 h-rem-24 text-center text-muted">
                      <i class="bi bi-gem text-xl"></i>
                      <span class="fw-semibold text-xs">Commodity</span>
                    </span>
                  </label>
                </div>
              </div>
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3 align-items-center">
            <div class="col-md-2">
              <label class="form-label mb-0">Icon</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <div class="">
                <div class="d-flex align-items-center">
                  <a href="#" class="avatar avatar-lg bg-warning rounded-circle text-white">
                    <img src="../../img/crypto/color/ada.svg" alt="..." />
                  </a>
                  <div class="hstack gap-2 ms-5">
                    <label for="file_upload" class="btn btn-sm btn-neutral">
                      <span>Upload</span>
                      <input type="file" name="file_upload" id="file_upload" class="visually-hidden">
                    </label>
                    <a href="#" class="btn d-inline-flex btn-sm btn-neutral text-danger">
                      <span>
                        <i class="bi bi-trash"></i>
                      </span>
                      <span class="d-none d-sm-block ms-2">Remove</span>
                    </a>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3 align-items-center">
            <div class="col-md-2">
              <label class="form-label mb-0">Category</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <label class="visually-hidden">Category</label>
              <select class="form-select">
                <option>Webpixels</option>
                <option>Apple</option>
                <option>Elrond</option>
              </select>
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3">
            <div class="col-md-2">
              <label class="form-label mb-0">Publishing options</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <div>
                <label class="form-label">Start date</label>
                <div class="input-group input-group-inline datepicker">
                  <span class="input-group-text pe-2">
                    <i class="bi bi-calendar"></i>
                  </span>
                  <input type="text" class="form-control" placeholder="Select date" data-input="data-input">
                </div>
              </div>
            </div>
          </div>
          <hr class="my-6" />
          <div class="row align-items-center g-3">
            <div class="col-md-2">
              <label class="form-label mb-0">Options</label>
            </div>
            <div class="col-md-8 col-xl-5">
              <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" name="switch_make_public" id="switch_make_public">
                <label class="form-check-label ms-2" for="switch_make_public">
                  Make the asset public
                </label>
              </div>
            </div>
          </div>
          <hr class="my-6 d-md-none" />
          <div class="d-flex d-md-none justify-content-end gap-2">
            <button type="button" class="btn btn-sm btn-neutral">Cancel</button>
            <button type="submit" class="btn btn-sm btn-primary">Save</button>
          </div>
        </main>
      </div>
        </div>
    </div>
</template>

<script setup>

</script>
<style scoped>
.result-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
}

.result-image {
  width: 100%; /* 이미지가 컨테이너 너비에 맞게 조정 */
  height: 300px; /* 비율 유지 */
  object-fit: cover;
  z-index: 1; /* 이미지가 아래에 위치하도록 설정 */
  opacity: 0.5;

}

.result-text {
  position: absolute; /* 절대 위치 설정 */
  top: 30%; /* 컨테이너의 중간 */
  left: 15%; /* 컨테이너의 중간 */
  transform: translate(-50%, -50%); /* 중앙 정렬 */
  color: white; /* 텍스트 색상 */
  padding: 10px; /* 여백 추가 */
  border-radius: 5px; /* 모서리 둥글게 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */
  font-size: 30px;
}

.result-text2-container {
  position: absolute; /* 절대 위치 설정 */
  top: 23%; /* 컨테이너의 중간 */
  left: 9.3%; /* 고정 위치 */
  z-index: 2; /* 텍스트가 이미지 위에 위치하도록 설정 */

  display: flex; /* 플렉스 박스 사용 */
}

.result-text2 {
  color: rgb(0, 0, 0); /* 텍스트 색상 */  
  padding: 10px; /* 여백 추가 */
  font-size: 50px;
  flex-grow: 1; /* 오른쪽 영역이 늘어나도록 설정 */
  margin-left: 10px; /* 텍스트 간격 */
}

.overlay {
  position: absolute; /* 절대 위치 설정 */
  top: 35%; /* user-info의 하단에 위치 */
  left: 50%; /* 가운데 정렬을 위해 left를 50%로 설정 */
  transform: translateX(-50%); /* 가운데 정렬 조정 */
  width: 80%; /* 너비를 60%로 설정하여 양쪽 20% 여백을 만듭니다 */
  background-color: rgba(255, 255, 255); /* 흰색 반투명 배경 */
  border-radius: 40px; /* 모서리 둥글게 */
  z-index: 1; /* 이미지 아래에 위치하도록 설정 */
  box-sizing: border-box; /* 패딩을 포함하여 전체 너비를 계산 */
}
.overlay-text {
  color: black; /* 텍스트 색상 */
  width: 100%;

  font-size: 24px; /* 텍스트 크기 조정 */
  margin: 2% 0; /* 위아래에 10%의 여백 추가 */
}

.table-container {
  position: relative; /* 자식 요소의 절대 위치 기준 설정 */
  z-index: 3; /* 테이블이 overlay 위에 위치하도록 설정 */
  margin-top: 20px; /* 테이블이 overlay와 겹치지 않도록 여백 추가 */
}

.container {
  padding: 0px 80px 0px 80px;
}

.flex-item {
  flex: 1;
  text-align: center;
}
</style>