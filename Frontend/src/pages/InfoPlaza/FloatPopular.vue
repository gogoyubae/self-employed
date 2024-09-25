<template>
    <div>
        <InfoPlazaHeader class="mb-5" />
        <div class="container">
            <div class="row">
                <CommercialHeader class="ms-10 me-5 col-1"/>
                <div class="col-3 me-5 mt-3">
                    <div class="mb-10">
                        <h4 class="mb-3">현위치</h4>
                        <div class=" mb-5">
                            <div class="card-body card_padding d-flex gap-3">
                                <i class="bi bi-geo-alt h-rem-7"></i>
                                <span class="d-inline text-muted">서울특별시 광진구 화양동</span>
                            </div>
                        </div>
                    </div>
                    <div>
                        <h4 class="mb-3">지역 선택</h4>
                            <div class="card-body card_padding d-flex gap-3">
                                <div
                                    class="text-muted text-primary-hover dropdown-toggle"
                                    id="locationDropdown"
                                    data-bs-toggle="dropdown"
                                    role="button"
                                >
                                <span class="text-muted pe-100">서울특별시 광진구 화양동</span>
                                    <ul class="dropdown-menu dropdown-menu-end w-80" aria-labelledby="locationDropdown">
                                        <li><a class="dropdown-item" href="#">서울특별시 광진구 화양동</a></li>
                                        <li><a class="dropdown-item" href="#">서울특별시 광진구 화양동</a></li>
                                        <li><a class="dropdown-item" href="#">서울특별시 광진구 화양동</a></li>
                                    </ul>
                                </div>
                            </div>
                    </div>
                </div>
            <div class="col-6 ms-10" ref="mapContainer" style="height: 70vh;"></div>

        </div>
    </div>
</div>
</template>

<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
import CommercialHeader from '@/components/infoplaza/CommercialHeader.vue';
import { onMounted, ref } from 'vue';

const mapContainer = ref(null);


onMounted(() => {
    loadKakaoMap(mapContainer.value);
});

// Load Kakao Map
const loadKakaoMap = (container) => {
    const script = document.createElement('script');
    script.src = `https://dapi.kakao.com/v2/maps/sdk.js?appkey=09118387dc78b55b2c58f3876095c5d2&autoload=false`;
    document.head.appendChild(script);

    script.onload = () => {
        window.kakao.maps.load(() => {
            const options = {
                center: new window.kakao.maps.LatLng(33.450701, 126.570667), // Center coordinates
                level: 3, // Zoom level
                maxLevel: 5 // Maximum zoom level
            };

            const mapInstance = new window.kakao.maps.Map(container, options); // Create map instance
        });
    };
};

</script>
<style>
.card_padding {
    padding-top: 3px;
    padding-bottom: 5px;
    padding-left: 0px;
    border: none;
    box-shadow: none; /* 그림자 제거 */
    border-bottom: 0.7px solid #D9D9D9; /* 밑에 라인 추가 */
    border-radius: 0; /* 둥근 테두리 제거 */

}

.pe-100{
    padding-right: 100px;
}

</style>