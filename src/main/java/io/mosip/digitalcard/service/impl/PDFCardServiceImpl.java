package io.mosip.digitalcard.service.impl;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.biometrics.util.ConvertRequestDto;
import io.mosip.biometrics.util.face.FaceDecoder;
import io.mosip.digitalcard.constant.*;
import io.mosip.digitalcard.dto.PDFSignatureRequestDto;
import io.mosip.digitalcard.dto.SignatureResponseDto;
import io.mosip.digitalcard.dto.SimpleType;
import io.mosip.digitalcard.service.CardGeneratorService;
import io.mosip.digitalcard.exception.DigitalCardServiceException;
import io.mosip.digitalcard.exception.IdentityNotFoundException;
import io.mosip.digitalcard.repositories.DigitalCardTransactionRepository;
import io.mosip.digitalcard.util.*;
import io.mosip.kernel.core.cbeffutil.spi.CbeffUtil;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.http.ResponseWrapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.pdfgenerator.exception.PDFGeneratorException;
import io.mosip.kernel.core.pdfgenerator.spi.PDFGenerator;
import io.mosip.kernel.core.qrcodegenerator.exception.QrcodeGenerationException;
import io.mosip.kernel.core.qrcodegenerator.spi.QrCodeGenerator;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.qrcode.generator.zxing.constant.QrVersion;
import io.mosip.vercred.CredentialsVerifier;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.opencv.core.Mat;
import org.opencv.core.MatOfByte;
import org.opencv.core.MatOfInt;
import org.opencv.core.MatOfRect;
import org.opencv.core.Rect;
import org.opencv.core.Size;
import org.opencv.imgcodecs.Imgcodecs;
import org.opencv.imgproc.Imgproc;
import org.opencv.objdetect.CascadeClassifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class PDFCardServiceImpl implements CardGeneratorService {


	/** The PDFServiceImpl logger. */
	Logger logger = DigitalCardRepoLogger.getLogger(PDFCardServiceImpl.class);

	private static final String DATETIME_PATTERN = "mosip.digitalcard.service.datetime.pattern";

	/** The Constant FILE_SEPARATOR. */
	public static final String FILE_SEPARATOR = File.separator;

	/** The Constant VALUE. */
	private static final String VALUE = "value";

	/** The Constant FACE. */
	private static final String FACE = "Face";

	/** The Constant APPLICANT_PHOTO. */
	private static final String APPLICANT_PHOTO = "ApplicantPhoto";

	/** The Constant QRCODE. */
	private static final String QRCODE = "QrCode";

	@Autowired
	private RestClient restApiClient;

	/** The pdf generator. */
	@Autowired
	private PDFGenerator pdfGenerator;

	/** The template generator. */
	@Autowired
	private TemplateGenerator templateGenerator;

	/** The utilities. */
	@Autowired
	private Utility utility;

	/** The qr code generator. */
	@Autowired
	private QrCodeGenerator<QrVersion> qrCodeGenerator;

	/** The cbeffutil. */
	@Autowired
	private CbeffUtil cbeffutil;

	/** The env. */
	@Autowired
	private Environment env;

	@Autowired
	DigitalCardTransactionRepository digitalCardTransactionRepository;

	@Autowired
	private CredentialsVerifier credentialsVerifier;

	@Value("${mosip.template-language}")
	private String templateLang;

	@Value("${mosip.supported-languages}")
	private String supportedLang;

	@Value("${mosip.digitalcard.service.uincard.lowerleftx}")
	private int lowerLeftX;

	@Value("${mosip.digitalcard.service.uincard.lowerlefty}")
	private int lowerLeftY;

	@Value("${mosip.digitalcard.service.uincard.upperrightx}")
	private int upperRightX;

	@Value("${mosip.digitalcard.service.uincard.upperrighty}")
	private int upperRightY;

	@Value("${mosip.digitalcard.service.uincard.signature.reason}")
	private String reason;

	@Value("${mosip.digitalcard.templateTypeCode:RPR_UIN_CARD_TEMPLATE}")
	private String uinCardTemplate;

	private static String piktyur;
	
	@Autowired
	private ObjectMapper objectMapper;

	public PDFCardServiceImpl() {
	}


    static {
        nu.pattern.OpenCV.loadShared();
        System.loadLibrary(org.opencv.core.Core.NATIVE_LIBRARY_NAME);
    }
	/*
	 * (non-Javadoc)
	 * 
	 * @see io.mosip.digitalcard.service.PDFService#
	 */
	public byte[] generateCard(org.json.JSONObject decryptedCredentialJson, String credentialType,
							   String password) {
		logger.debug("PDFServiceImpl::getDocuments()::entry");
		boolean isGenerated=false;
		String uin = null;
		boolean isPhotoSet=false;
		String individualBio = null;
		Map<String, Object> attributes = new LinkedHashMap<>();
		String template = uinCardTemplate;
		byte[] pdfbytes = null;
		try {
			if(decryptedCredentialJson.has("biometrics")){
				individualBio = decryptedCredentialJson.getString("biometrics");
				String individualBiometric = new String(individualBio);
				isPhotoSet = setApplicantPhoto(individualBiometric, attributes);
				attributes.put("isPhotoSet",isPhotoSet);
			}
			uin = decryptedCredentialJson.getString("UIN");
			if (credentialType.equalsIgnoreCase("qrcode")) {
				boolean isQRcodeSet = setQrCode(decryptedCredentialJson.toString(), attributes,isPhotoSet);
				InputStream uinArtifact = templateGenerator.getTemplate(template, attributes, templateLang);
				pdfbytes = generateUinCard(uinArtifact, password);
			} else {
				if (!isPhotoSet) {
					logger.debug(DigitalCardServiceErrorCodes.APPLICANT_PHOTO_NOT_SET.name());
				}
				setTemplateAttributes(decryptedCredentialJson, attributes);
				attributes.put(IdType.UIN.toString(), uin);
				boolean isQRcodeSet = setQrCode(decryptedCredentialJson.toString(), attributes,isPhotoSet);
				if (!isQRcodeSet) {
					logger.debug(DigitalCardServiceErrorCodes.QRCODE_NOT_SET.name());
				}
				// getting template and placing original valuespng
				InputStream uinArtifact = templateGenerator.getTemplate(template, attributes, templateLang);
				if (uinArtifact == null) {
					logger.error(DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.name());
					throw new DigitalCardServiceException(
							DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.getErrorCode(),DigitalCardServiceErrorCodes.TEM_PROCESSING_FAILURE.getErrorMessage());
				}
				pdfbytes = generateUinCard(uinArtifact, password);
				//to be deleted when making Jar
				InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(pdfbytes));
                File pdfFile = new File("src/main/resources/uin.pdf");
                OutputStream os = new FileOutputStream(pdfFile);
                os.write(pdfbytes);
                os.close();
			}
			

		}

		catch (QrcodeGenerationException e) {
			logger.error(DigitalCardServiceErrorCodes.QRCODE_NOT_GENERATED.getErrorMessage(), e);
		}  catch (PDFGeneratorException e) {
			logger.error(DigitalCardServiceErrorCodes.PDF_NOT_GENERATED.getErrorMessage() ,e);
		}catch (Exception ex) {
			logger.error(PDFGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorMessage() ,ex);
		}
		logger.debug("PDFServiceImpl::getDocuments()::exit");
		return pdfbytes;
	}

	/**
	 * Sets the qr code.
	 *
	 * @param attributes   the attributes
	 * @return true, if successful
	 * @throws QrcodeGenerationException                          the qrcode
	 *                                                            generation
	 *                                                            exception
	 * @throws IOException                                        Signals that an
	 *                                                            I/O exception has
	 *                                                            occurred.
	 * @throws QrcodeGenerationException
	 */
	private boolean setQrCode(String qrString, Map<String, Object> attributes,boolean isPhotoSet)
			throws IOException, QrcodeGenerationException {
		boolean isQRCodeSet = false;
						
		JSONObject qrJsonObj = objectMapper.readValue(qrString, JSONObject.class);
		JSONObject test = new JSONObject();
		JSONObject sb = new JSONObject();
		
		if(isPhotoSet) {
			qrJsonObj.remove("biometrics");
		}

		String compressedBase64 = null;
		if (piktyur != null) {
			compressedBase64 = generateFace();
			if(compressedBase64 != null) {
				test.put("img", compressedBase64);
			}
		}
		else {
			System.out.println("WAlang piktuyr");
		}
		
		String fn = removeSide(qrJsonObj.get("fn").toString());
		String mn = removeSide(qrJsonObj.get("mn").toString());
		String ln = removeSide(qrJsonObj.get("ln").toString());
		String bf = removeSideBf(qrJsonObj.get("BF").toString());
		String sx = removeSideGen(qrJsonObj.get("gen").toString());
		String dob2 = removeSideDate(qrJsonObj.get("dob").toString());
		String pob = removeSide(qrJsonObj.get("pob").toString());
		sb.put("PCN", qrJsonObj.get("PCN"));
				
		String forSigning = "{ \"i\": \"PSA\"," +
				" \"sb\": {   \"sf\": \"\",   " +
				"\"ln\": \""+ln+"\",   "+
				"\"fn\": \""+fn+"\",   "+
				"\"mn\": \""+mn+"\",   "+
				"\"s\": \""+sx+"\",   "+
				"\"BF\": \""+bf+"\",   "+
				"\"DOB\": \""+dob2+"\",   "+
				"\"POB\": \""+pob+"\",   "+
				"\"PCN\": \""+qrJsonObj.get("PCN")+"\" },"+
				"\"img\": \""+compressedBase64+"\"}";

		System.out.println(forSigning);
		String signedSignature = null;
		try {
			signedSignature = digitallySignSignature(forSigning);
			System.out.println("SIGNATURA : " + signedSignature);
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
		String forQR = "{ \"i\": \"PSA\"," +
				" \"sb\": {   \"sf\": \"\",   " +
				"\"ln\": \""+ln+"\",   "+
				"\"fn\": \""+fn+"\",   "+
				"\"mn\": \""+mn+"\",   "+
				"\"s\": \""+sx+"\",   "+
				"\"BF\": \""+bf+"\",   "+
				"\"DOB\": \""+dob2+"\",   "+
				"\"POB\": \""+pob+"\",   "+
				"\"PCN\": \""+qrJsonObj.get("PCN")+"\" },"+
				"\"img\": \""+compressedBase64+"\","+
				"\"si\": \""+signedSignature+"\"}";
		
		byte[] qrCodeBytes = qrCodeGenerator.generateQrCode(forQR, QrVersion.V20);
//		byte[] qrCodeBytes = qrCodeGenerator.generateQrCode(test.toString(), QrVersion.V25);
		if (qrCodeBytes != null) {
			String imageString = Base64.encodeBase64String(qrCodeBytes);
			attributes.put(QRCODE, "data:image/png;base64," + imageString);
			isQRCodeSet = true;
		}

		return isQRCodeSet;
	}

	/**
	 * Sets the applicant photo.
	 *
	 *            the response
	 * @param attributes
	 *            the attributes
	 * @return true, if successful
	 * @throws Exception
	 *             the exception
	 */
	private boolean setApplicantPhoto(String individualBio, Map<String, Object> attributes) throws Exception {
		ConvertRequestDto convertRequestDto = new ConvertRequestDto();
		String value = individualBio;
		boolean isPhotoSet = false;

		if (value != null) {
			CbeffToBiometricUtil util = new CbeffToBiometricUtil(cbeffutil);
			List<String> subtype = new ArrayList<>();
			byte[] photoByte = util.getImageBytes(value, FACE, subtype);
			convertRequestDto.setVersion("ISO19794_5_2011");
			convertRequestDto.setInputBytes(photoByte);
			if (photoByte != null) {
				byte[] data = FaceDecoder.convertFaceISOToImageBytes(convertRequestDto);
				String encodedData = StringUtils.newStringUtf8(Base64.encodeBase64(data, false));
				piktyur = encodedData;
				attributes.put(APPLICANT_PHOTO, "data:image/png;base64," + encodedData);
				isPhotoSet = true;
			}
		}
		return isPhotoSet;
	}

	/**
	 * Gets the artifacts.
	 *
	 * @param attribute    the attribute
	 * @return the artifacts
	 * @throws IOException    Signals that an I/O exception has occurred.
	 * @throws ParseException
	 */
	@SuppressWarnings("unchecked")
	private void setTemplateAttributes(org.json.JSONObject demographicIdentity, Map<String, Object> attribute)
			throws Exception {
		try {
			if (demographicIdentity == null)
				throw new IdentityNotFoundException(DigitalCardServiceErrorCodes.IDENTITY_NOT_FOUND.getErrorCode(),DigitalCardServiceErrorCodes.IDENTITY_NOT_FOUND.getErrorMessage());

			String mapperJsonString = utility.getIdentityMappingJson(utility.getConfigServerFileStorageURL(),
					utility.getIdentityJson());
			JSONObject mapperJson = objectMapper.readValue(mapperJsonString, JSONObject.class);
			JSONObject mapperIdentity = utility.getJSONObject(mapperJson,
					utility.getDemographicIdentity());

			List<String> mapperJsonKeys = new ArrayList<>(mapperIdentity.keySet());
			for (String key : mapperJsonKeys) {
				LinkedHashMap<String, String> jsonObject = utility.getJSONValue(mapperIdentity, key);
				Object obj = null;
				String values = jsonObject.get(VALUE);
				for (String value : values.split(",")) {
					// Object object = demographicIdentity.get(value);
					Object object = demographicIdentity.has(value)?demographicIdentity.get(value):null;
					if (object != null) {
						try {
							obj = new JSONParser().parse(object.toString());
						} catch (Exception e) {
							obj = object;
						}

						if (obj instanceof JSONArray && !key.equalsIgnoreCase("bestTwoFingers")) {
							// JSONArray node = JsonUtil.getJSONArray(demographicIdentity, value);
							SimpleType[] jsonValues = Utility.mapJsonNodeToJavaObject(SimpleType.class, (JSONArray) obj);
							for (SimpleType jsonValue : jsonValues) {
								if (supportedLang.contains(jsonValue.getLanguage()))
									attribute.put(value + "_" + jsonValue.getLanguage(), jsonValue.getValue());
							}
						} else if (object instanceof JSONObject) {
							JSONObject json = (JSONObject) object;
							attribute.put(value, (String) json.get(VALUE));
						} else {
							attribute.put(value, String.valueOf(object));
						}
					}

				}
			}
			} catch (JsonParseException | JsonMappingException | DigitalCardServiceException e) {
				logger.error("Error while parsing Json file" ,e);
			}

	}

	private byte[] generateUinCard(InputStream in, String password) {
		logger.debug("UinCardGeneratorImpl::generateUinCard()::entry");
		byte[] pdfSignatured=null;
		ByteArrayOutputStream out = null;
		try {
			out = (ByteArrayOutputStream) pdfGenerator.generate(in);
			PDFSignatureRequestDto request = new PDFSignatureRequestDto(lowerLeftX, lowerLeftY, upperRightX,
					upperRightY, reason, 1, password);
			request.setApplicationId("KERNEL");
			request.setReferenceId("SIGN");
			request.setData(Base64.encodeBase64String(out.toByteArray()));
			DateTimeFormatter format = DateTimeFormatter.ofPattern(env.getProperty(DATETIME_PATTERN));
			LocalDateTime localdatetime = LocalDateTime
					.parse(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)), format);

			request.setTimeStamp(DateUtils.getUTCCurrentDateTimeString());
			RequestWrapper<PDFSignatureRequestDto> requestWrapper = new RequestWrapper<>();

			requestWrapper.setRequest(request);
			requestWrapper.setRequesttime(localdatetime);
			ResponseWrapper<?> responseWrapper;
			SignatureResponseDto signatureResponseDto;

			responseWrapper= restApiClient.postApi(ApiName.PDFSIGN, null, "",""
					, MediaType.APPLICATION_JSON,requestWrapper, ResponseWrapper.class);


			if (responseWrapper.getErrors() != null && !responseWrapper.getErrors().isEmpty()) {
				ServiceError error = responseWrapper.getErrors().get(0);
				throw new DigitalCardServiceException(error.getMessage());
			}
			signatureResponseDto = objectMapper.readValue(objectMapper.writeValueAsString(responseWrapper.getResponse()),
					SignatureResponseDto.class);

			pdfSignatured = Base64.decodeBase64(signatureResponseDto.getData());

		} catch (Exception e) {
			logger.error(io.mosip.kernel.pdfgenerator.itext.constant.PDFGeneratorExceptionCodeConstant.PDF_EXCEPTION.getErrorMessage(),e.getMessage()
					+ ExceptionUtils.getStackTrace(e));
		}
		logger.debug("UinCardGeneratorImpl::generateUinCard()::exit");

		return pdfSignatured;
	}
	
	private String generateFace() throws IOException {
		if (piktyur == null) {
			return "No Image";
		}
		
		byte[] sData = Base64.decodeBase64(piktyur);
		
		Mat src = Imgcodecs.imdecode(new MatOfByte(sData), Imgcodecs.CV_LOAD_IMAGE_UNCHANGED);
		int image_x_coor = src.width() / 2;
		int image_y_coor = src.height() / 2;
		
		String xmlFile = "src/main/resources/haarcascade_frontalface_default.xml";
		CascadeClassifier classifier = new CascadeClassifier(xmlFile);
		
		MatOfRect faceDetections = new MatOfRect();
		classifier.detectMultiScale(src, faceDetections);
		
		Rect rect_crop = null;
		
		Rect[] faces = faceDetections.toArray();
		Rect found_face = null;
		int faces_length = faces.length;
		
		if(faces.length == 0) {
			return "No Image";
		}else if(faces_length == 1) {
			found_face = faces[0];
		}else {
			List<Double> list_centers = new ArrayList<>();
			for(Rect rect: faces) {
				int x = rect.x;
				int y = rect.y;				
				double x_distance = Math.pow(x - image_x_coor, 2);
				double y_distance = Math.pow(y - image_y_coor, 2);
				double distance = Math.sqrt(x_distance + y_distance);
				list_centers.add(distance);
			}
			double min_val = Collections.min(list_centers);
			int index_min_val = list_centers.indexOf(min_val);
			found_face = faces[index_min_val];
		}
		
		rect_crop = new Rect(found_face.x, found_face.y,found_face.x + found_face.width, found_face.y + found_face.height);		
		
		try {
			Mat image_row = new Mat(src, rect_crop);
			
			Imgproc.cvtColor(image_row, image_row, Imgproc.COLOR_RGB2GRAY);

			Imgproc.resize(image_row, image_row, new Size(45,58));
			MatOfInt map = new MatOfInt(Imgcodecs.IMWRITE_WEBP_QUALITY, 30);
			
			MatOfByte mem = new MatOfByte();
			Imgcodecs.imencode(".webp", image_row, mem, map);

			try {
				String compressedB64 = Base64.encodeBase64String(mem.toArray());
				return compressedB64;
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			return null;
			
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		return null;
		
	}
	
	private String removeSide(String s) {
		String codeString = s.replace("[{language=eng, value=","");
		String codeString2 = codeString.replace("}]", "");
		return codeString2;
	}
	
	private String removeSideDate(String s) {
		String s1 = s.replace("/", "-");
		String s2 = s1.replace("Date of Birth ", "");
		return s2;
	}
	
	private String removeSideGen(String s) {
		String codeString = s.replace("[{language=eng, value=","");
		String codeString2 = codeString.replace("}]", "");
		String codeString3 = null;
		if(codeString2 == "Female") {
			codeString3 = "f";
		}
		else {
			codeString3 = "m";
		}
		
		return codeString3;
	}
	
	private String removeSideBf(String bio) {
		String rString = null;
		try {
			String lrString = bio.substring(bio.indexOf("{rank=")+6,bio.indexOf(", subType"));
			String rrBString = bio.substring(bio.indexOf(", {rank=")+8,bio.length());
			String rrString = rrBString.substring(0,rrBString.indexOf(", subType"));
			return rString = "[" + lrString + "," + rrString + "]";
		}
		catch (Exception f) {
			f.printStackTrace();
		}
		return rString;
	}
	
	
	private String digitallySignSignature(String stringToSign) throws CryptoException {
        var msg = stringToSign.getBytes(StandardCharsets.UTF_8);

        var privateKeyBytes = Base64.decodeBase64("dazPBzb3e32NKQxTUm/HsEKMfHaCqFM+gf2jCQk0SCyBTlmwEgfcDV5QD/Ml9wX3WeYMQy5pMfjX+eDxvODNZA==");
        var publicKeyBytes = Base64.decodeBase64("gU5ZsBIH3A1eUA/zJfcF91nmDEMuaTH41/ng8bzgzWQ=");

        var privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        // Generate new signature
        Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();
        var actualSignature = Base64.encodeBase64String(signature);
        
		return actualSignature;
	}
}
	
